Response:
The user is asking for an analysis of a Python file which is part of the Frida dynamic instrumentation tool. The file is `mesonmain.py` located within the Frida's Meson build system configuration.

Here's a breakdown of how to analyze the code and address the user's request:

1. **Understand the Context:** The file is named `mesonmain.py` and is within the Meson build system's interpreter. This immediately suggests it provides functions that are accessible within Meson build files (`meson.build`). It's a bridge between the build definition and the underlying build system logic.

2. **Identify Core Functionality:**  Scan the class `MesonMain` and its methods. The names of the methods are quite descriptive (e.g., `add_install_script_method`, `get_compiler_method`, `override_dependency_method`). Group these methods into categories based on what they seem to do.

3. **Relate to Reverse Engineering:** Think about how the functionalities provided by these methods could be relevant to reverse engineering tasks. Frida is a dynamic instrumentation tool, so the connection should be focused on how these build-time configurations might influence or support the building of Frida itself, which is used for reverse engineering.

4. **Consider Low-Level Interactions:** Look for methods that hint at interactions with the underlying operating system, compilers, or build processes. Methods related to finding programs, overriding dependencies, and managing scripts often touch on these aspects.

5. **Analyze Logic and Assumptions:** For methods that involve more complex logic (like `override_dependency_method`), try to follow the flow and identify any assumptions made about the input or the system's state. Consider what could go wrong if these assumptions are violated.

6. **Trace User Interaction:**  Think about how a user would interact with Frida's build system. They would likely edit `meson.build` files and run Meson commands. Trace how these actions could lead to the execution of the methods defined in this file.

7. **Provide Concrete Examples:**  For each category of functionality, create specific examples that illustrate how it relates to reverse engineering, low-level details, logic, and potential user errors.

**Detailed Thought Process for Specific Sections:**

* **Listing Functionality:**  Simply list the public methods of the `MesonMain` class, as their names generally indicate their function.

* **Reverse Engineering Relation:** Focus on how Frida itself, being a reverse engineering tool, uses its build system. Methods like `add_install_script` (for installing Frida components), `get_compiler` (for building Frida), and `override_dependency` (for managing Frida's dependencies) are relevant. The example of overriding a library to use a debug version is a concrete way this could be used in a reverse engineering context (e.g., when developing or debugging Frida itself).

* **Binary/Kernel/Framework:** Look for methods that deal with executables, scripts, and dependencies. The `add_*_script` methods involve executing scripts, which can interact with the OS. The `get_compiler` method is directly related to binary compilation. Mentioning the potential for scripts to interact with the Android framework if Frida is being built for Android provides a relevant example.

* **Logical Reasoning:** The `override_dependency_method` is a good candidate. The logic handles cases where dependencies are overridden. The example shows how overriding a dependency affects the build process. The assumptions about the input dependency being valid are important.

* **User/Programming Errors:** Consider common mistakes when using build systems. Incorrect file paths in scripts, trying to override a non-existent dependency, or providing the wrong type of argument to a function are all realistic errors.

* **User Steps to Reach Here:** Explain the standard Meson workflow. The user runs `meson setup` to configure the build, which involves interpreting the `meson.build` files. The `MesonMain` class is instantiated during this interpretation.

**Self-Correction/Refinement:**

* Initially, I might have just listed the methods without categorizing them. However, grouping them by functionality makes the explanation clearer.
*  I need to make sure the reverse engineering examples are specifically relevant to *how Frida is built*, as this file is part of Frida's build system, not Frida's runtime.
* I should avoid overly technical jargon and explain concepts in a way that is understandable to someone who might not be deeply familiar with Meson's internals.
*  It's important to emphasize that this file is part of the *build system* for Frida, and the reverse engineering connection is primarily about how Frida itself is constructed.
这是 `frida/subprojects/frida-clr/releng/meson/mesonbuild/interpreter/mesonmain.py` 文件的功能列表，以及它与逆向方法、二进制底层、Linux/Android 内核及框架知识、逻辑推理、用户错误和调试线索的关系说明：

**文件功能列表:**

这个 Python 文件定义了一个名为 `MesonMain` 的类，该类是 Meson 构建系统中用于处理 `meson` 全局命名空间下可用函数的关键组件。这些函数允许在 `meson.build` 文件中执行各种构建相关的操作。以下是其主要功能：

1. **脚本执行控制:**
    * `add_install_script`:  定义在安装阶段执行的脚本。
    * `add_postconf_script`: 定义在配置阶段之后执行的脚本。
    * `add_dist_script`: 定义在创建发布包时执行的脚本。

2. **路径信息获取:**
    * `current_source_dir`: 获取当前 `meson.build` 文件所在的源代码目录。
    * `current_build_dir`: 获取当前 `meson.build` 文件对应的构建目录。
    * `build_root`: (已弃用) 获取顶层构建目录。
    * `source_root`: (已弃用) 获取顶层源代码目录。
    * `project_source_root`: 获取当前项目的源代码根目录。
    * `project_build_root`: 获取当前项目的构建根目录。
    * `global_source_root`: 获取全局源代码根目录。
    * `global_build_root`: 获取全局构建根目录。

3. **构建环境查询:**
    * `backend`: 获取当前使用的构建后端 (例如 Ninja, Xcode)。
    * `can_run_host_binaries`: 检查是否可以运行主机平台的二进制文件（用于交叉编译）。
    * `is_cross_build`: 检查是否是交叉编译。
    * `get_compiler`: 获取指定语言的编译器对象。
    * `is_unity`: 检查是否启用了 Unity 构建。
    * `is_subproject`: 检查当前项目是否是子项目。

4. **依赖管理:**
    * `install_dependency_manifest`: 设置依赖清单文件的名称。
    * `override_find_program`:  覆盖 Meson 查找特定程序的方式。
    * `override_dependency`: 覆盖 Meson 查找特定依赖项的方式。

5. **项目信息获取:**
    * `project_version`: 获取当前项目的版本。
    * `project_license`: 获取当前项目的许可证。
    * `project_license_files`: 获取当前项目许可证文件的列表。
    * `project_name`: 获取当前项目的名称。
    * `version`: 获取 Meson 的版本。

6. **外部属性和交叉编译属性:**
    * `get_cross_property`: (已弃用) 获取交叉编译属性。
    * `get_external_property`: 获取指定机器（主机或构建机）的外部属性。
    * `has_external_property`: 检查指定机器是否具有特定的外部属性。

7. **环境变量管理:**
    * `add_devenv`:  在构建环境中添加或修改环境变量。

8. **构建选项:**
    * `build_options`: 获取用户定义的构建选项字符串。

**与逆向方法的关系及举例:**

这个文件本身是 Frida 构建系统的一部分，它的功能主要用于配置 Frida 的构建过程。与逆向方法的直接关系体现在以下几个方面：

* **构建 Frida 工具本身:** Frida 作为一个动态插桩工具，其自身的构建过程需要使用 Meson 这样的构建系统。`mesonmain.py` 中定义的功能用于配置 Frida 的编译、链接、安装等步骤。逆向工程师如果想理解 Frida 的构建过程、修改 Frida 的源代码或者为特定平台编译 Frida，就需要理解这些功能的作用。
* **定制构建过程:**  逆向工程师可能需要定制 Frida 的构建过程，例如：
    * **使用特定的编译器版本:** 可以通过 `override_find_program` 覆盖默认的编译器查找方式，指定特定的编译器路径。
    * **链接特定的库版本:** 可以通过 `override_dependency` 覆盖 Frida 依赖的库，例如使用特定版本的 GLib 或 V8。
    * **添加自定义的构建步骤:** 可以使用 `add_install_script` 或其他脚本执行函数，在构建过程中执行自定义的脚本，例如拷贝额外的文件或执行特定的后处理操作。
    * **针对特定平台编译:**  理解 `is_cross_build` 和 `get_compiler` 等函数有助于进行交叉编译，例如为 Android 或 iOS 设备构建 Frida。

**举例说明:**

假设逆向工程师想要使用一个特定版本的 V8 引擎来构建 Frida-CLR。他们可以在 Frida-CLR 的 `meson.build` 文件中使用 `override_dependency` 函数来指定 V8 库的路径：

```meson
v8_dep = dependency('v8', dirs: '/path/to/specific/v8/installation')
meson.override_dependency('v8', v8_dep)
```

**涉及二进制底层，Linux, Android 内核及框架的知识及举例:**

* **二进制底层:**
    * `get_compiler`:  直接涉及到编译器的调用，编译器负责将源代码转换为机器码（二进制）。理解编译原理、链接过程等二进制底层知识有助于理解 `get_compiler` 的作用和如何选择合适的编译器选项。
    * `add_install_script`, `add_postconf_script`, `add_dist_script`: 这些函数允许在构建过程中执行脚本，这些脚本可以执行与二进制文件操作相关的任务，例如 strip 符号、打包二进制文件等。
* **Linux 内核:**
    *  在为 Linux 构建 Frida 时，`get_compiler` 获取的编译器会生成针对 Linux 平台的二进制代码。构建脚本可能需要处理与 Linux 特有的库（如 glibc）的依赖关系。
* **Android 内核及框架:**
    * 当为 Android 构建 Frida 时，通常是交叉编译。`is_cross_build` 会返回 `true`。`get_compiler` 会获取 Android NDK 提供的交叉编译器。
    * 构建脚本可能需要处理 Android 特有的库依赖、ABI (Application Binary Interface) 问题，以及与 Android 系统框架的交互。例如，Frida 需要注入到 Android 进程中，这涉及到对 Android 进程管理和安全机制的理解。
    * `add_install_script` 可以用于将编译好的 Frida 服务端组件推送到 Android 设备的目标目录。

**举例说明:**

在为 Android 构建 Frida 时，`meson.build` 文件中可能会使用 `get_compiler` 来获取 ARM 架构的编译器：

```meson
host_c_compiler = meson.get_compiler('c')
android_c_compiler = meson.get_compiler('c', native: false) # 获取非本地机器的编译器，即交叉编译器
```

**逻辑推理及假设输入与输出:**

* **`override_dependency_method` 的逻辑推理:**
    * **假设输入:**
        * `name`:  要覆盖的依赖项的名称，例如 "glib-2.0"。
        * `dep`:  表示新依赖项的对象，包含库的路径、头文件路径等信息。
        * `kwargs`:  包含可选参数，例如 `native` (指定是主机平台还是目标平台的依赖项)，`static` (指定是静态库还是动态库)。
    * **逻辑:** 该方法首先检查是否已经存在对该依赖项的覆盖。如果存在，并且不是 permissive 模式，则抛出异常。否则，将新的依赖项信息存储到 `build.dependency_overrides` 字典中。
    * **输出:**  如果覆盖成功，则没有返回值。如果覆盖失败（例如，尝试覆盖已存在的依赖项），则会抛出 `InterpreterException`。
* **`can_run_host_binaries_method` 的逻辑推理:**
    * **假设输入:** 无。
    * **逻辑:**  该方法检查是否是交叉编译，并且是否需要可执行文件包装器 (`exe_wrapper`)。如果需要包装器但未提供，则返回 `false`，否则返回 `true`。
    * **输出:** `True` 或 `False`，表示是否可以在构建过程中运行主机平台的二进制文件。

**用户或编程常见的使用错误及举例:**

* **在 `add_install_script` 中使用不存在的文件路径:**
    ```meson
    meson.add_install_script('my_install_script.sh', '/path/to/nonexistent/file.txt')
    ```
    **错误:**  Meson 无法找到 `/path/to/nonexistent/file.txt`，导致构建失败。
* **错误地使用 `override_dependency` 覆盖一个核心依赖项，导致编译错误:**
    ```meson
    # 错误地尝试覆盖 'glib-2.0'，但提供了错误的库文件
    glib_dep = dependency('glib-2.0', include_directories: '/some/wrong/path')
    meson.override_dependency('glib-2.0', glib_dep)
    ```
    **错误:**  后续编译步骤可能因为找不到正确的 GLib 头文件或库文件而失败。
* **在 `get_compiler` 中指定了不存在的语言:**
    ```meson
    cpp_compiler = meson.get_compiler('objective-c++') # 如果项目中没有 Objective-C++ 代码
    ```
    **错误:**  会抛出 `InterpreterException`，因为 Meson 没有找到名为 'objective-c++' 的编译器。
* **在需要主机平台程序时，错误地假设 `can_run_host_binaries` 返回 `true`，但实际是交叉编译且未配置 `exe_wrapper`:**
    ```meson
    if meson.can_run_host_binaries():
        run_host_tool = find_program('my_host_tool')
        # ... 执行主机工具 ...
    ```
    **错误:**  在交叉编译且未配置 `exe_wrapper` 的情况下，`meson.can_run_host_binaries()` 返回 `false`，但代码中假设可以运行主机工具，导致构建逻辑错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写或修改 `meson.build` 文件:** 用户为了配置 Frida 的构建过程，会编辑 `frida/subprojects/frida-clr/releng/meson/meson.build` 文件（或其他相关的 `meson.build` 文件）。在这个文件中，他们会调用 `meson` 对象的方法，例如 `meson.add_install_script()`, `meson.get_compiler()`, `meson.override_dependency()` 等。

2. **用户运行 Meson 配置命令:**  在项目根目录下，用户会执行类似 `meson setup builddir` 的命令来配置构建。

3. **Meson 解析 `meson.build` 文件:** Meson 的解释器会读取并解析 `meson.build` 文件。当遇到 `meson.xxx()` 这样的函数调用时，解释器会查找 `mesonmain.py` 文件中对应的 `xxx_method` 方法。

4. **执行 `mesonmain.py` 中的方法:**  Meson 解释器会实例化 `MesonMain` 类，并调用与 `meson.build` 文件中调用的函数相对应的方法。例如，如果 `meson.build` 中有 `meson.get_compiler('c')`，则会执行 `mesonmain.py` 中的 `get_compiler_method`。

5. **方法执行并影响构建状态:**  这些方法会修改 Meson 的内部状态，例如注册安装脚本、设置编译器信息、覆盖依赖项等。这些状态信息会被 Meson 用于后续的构建步骤。

**调试线索:**

如果构建过程中出现问题，理解用户操作如何到达 `mesonmain.py` 中的特定方法可以作为调试线索：

* **查看 `meson.build` 文件:**  检查用户编辑的 `meson.build` 文件，找到导致问题的 `meson.xxx()` 函数调用。
* **分析错误信息:** Meson 的错误信息通常会指出哪个 `meson.build` 文件的哪一行代码导致了问题。
* **使用 Meson 的调试功能:** Meson 提供了一些调试功能，例如可以输出构建过程中的变量值。
* **理解 `mesonmain.py` 中方法的逻辑:**  理解特定方法的功能和参数，可以帮助判断用户在 `meson.build` 文件中的使用是否正确。
* **检查 Meson 的日志文件:** Meson 会生成日志文件，其中包含了构建过程的详细信息，可以用来追踪问题的根源。

总而言之，`mesonmain.py` 是 Frida 构建系统的核心组成部分，理解其功能对于理解 Frida 的构建过程、定制构建以及调试构建问题至关重要。它连接了用户在 `meson.build` 文件中定义的构建意图和 Meson 构建系统的实际执行。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/interpreter/mesonmain.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2021 The Meson development team
# Copyright © 2021-2024 Intel Corporation
from __future__ import annotations

import copy
import os
import typing as T

from .. import mesonlib
from .. import dependencies
from .. import build
from .. import mlog, coredata

from ..mesonlib import MachineChoice, OptionKey
from ..programs import OverrideProgram, ExternalProgram
from ..interpreter.type_checking import ENV_KW, ENV_METHOD_KW, ENV_SEPARATOR_KW, env_convertor_with_method
from ..interpreterbase import (MesonInterpreterObject, FeatureNew, FeatureDeprecated,
                               typed_pos_args,  noArgsFlattening, noPosargs, noKwargs,
                               typed_kwargs, KwargInfo, InterpreterException)
from .primitives import MesonVersionString
from .type_checking import NATIVE_KW, NoneType

if T.TYPE_CHECKING:
    from typing_extensions import Literal, TypedDict

    from ..compilers import Compiler
    from ..interpreterbase import TYPE_kwargs, TYPE_var
    from ..mesonlib import ExecutableSerialisation
    from .interpreter import Interpreter

    class FuncOverrideDependency(TypedDict):

        native: mesonlib.MachineChoice
        static: T.Optional[bool]

    class AddInstallScriptKW(TypedDict):

        skip_if_destdir: bool
        install_tag: str
        dry_run: bool

    class NativeKW(TypedDict):

        native: mesonlib.MachineChoice

    class AddDevenvKW(TypedDict):
        method: Literal['set', 'prepend', 'append']
        separator: str


class MesonMain(MesonInterpreterObject):
    def __init__(self, build: 'build.Build', interpreter: 'Interpreter'):
        super().__init__(subproject=interpreter.subproject)
        self.build = build
        self.interpreter = interpreter
        self.methods.update({'add_devenv': self.add_devenv_method,
                             'add_dist_script': self.add_dist_script_method,
                             'add_install_script': self.add_install_script_method,
                             'add_postconf_script': self.add_postconf_script_method,
                             'backend': self.backend_method,
                             'build_options': self.build_options_method,
                             'build_root': self.build_root_method,
                             'can_run_host_binaries': self.can_run_host_binaries_method,
                             'current_source_dir': self.current_source_dir_method,
                             'current_build_dir': self.current_build_dir_method,
                             'get_compiler': self.get_compiler_method,
                             'get_cross_property': self.get_cross_property_method,
                             'get_external_property': self.get_external_property_method,
                             'global_build_root': self.global_build_root_method,
                             'global_source_root': self.global_source_root_method,
                             'has_exe_wrapper': self.has_exe_wrapper_method,
                             'has_external_property': self.has_external_property_method,
                             'install_dependency_manifest': self.install_dependency_manifest_method,
                             'is_cross_build': self.is_cross_build_method,
                             'is_subproject': self.is_subproject_method,
                             'is_unity': self.is_unity_method,
                             'override_dependency': self.override_dependency_method,
                             'override_find_program': self.override_find_program_method,
                             'project_build_root': self.project_build_root_method,
                             'project_license': self.project_license_method,
                             'project_license_files': self.project_license_files_method,
                             'project_name': self.project_name_method,
                             'project_source_root': self.project_source_root_method,
                             'project_version': self.project_version_method,
                             'source_root': self.source_root_method,
                             'version': self.version_method,
                             })

    def _find_source_script(
            self, name: str, prog: T.Union[str, mesonlib.File, build.Executable, ExternalProgram],
            args: T.List[str]) -> 'ExecutableSerialisation':
        largs: T.List[T.Union[str, build.Executable, ExternalProgram]] = []

        if isinstance(prog, (build.Executable, ExternalProgram)):
            FeatureNew.single_use(f'Passing executable/found program object to script parameter of {name}',
                                  '0.55.0', self.subproject, location=self.current_node)
            largs.append(prog)
        else:
            if isinstance(prog, mesonlib.File):
                FeatureNew.single_use(f'Passing file object to script parameter of {name}',
                                      '0.57.0', self.subproject, location=self.current_node)
            found = self.interpreter.find_program_impl([prog])
            largs.append(found)

        largs.extend(args)
        es = self.interpreter.backend.get_executable_serialisation(largs, verbose=True)
        es.subproject = self.interpreter.subproject
        return es

    def _process_script_args(
            self, name: str, args: T.Sequence[T.Union[
                str, mesonlib.File, build.BuildTarget, build.CustomTarget,
                build.CustomTargetIndex,
                ExternalProgram,
            ]]) -> T.List[str]:
        script_args = []  # T.List[str]
        new = False
        for a in args:
            if isinstance(a, str):
                script_args.append(a)
            elif isinstance(a, mesonlib.File):
                new = True
                script_args.append(a.rel_to_builddir(self.interpreter.environment.source_dir))
            elif isinstance(a, (build.BuildTarget, build.CustomTarget, build.CustomTargetIndex)):
                new = True
                script_args.extend([os.path.join(a.get_source_subdir(), o) for o in a.get_outputs()])

                # This feels really hacky, but I'm not sure how else to fix
                # this without completely rewriting install script handling.
                # This is complicated by the fact that the install target
                # depends on all.
                if isinstance(a, build.CustomTargetIndex):
                    a.target.build_by_default = True
                else:
                    a.build_by_default = True
            else:
                script_args.extend(a.command)
                new = True

        if new:
            FeatureNew.single_use(
                f'Calling "{name}" with File, CustomTarget, Index of CustomTarget, '
                'Executable, or ExternalProgram',
                '0.55.0', self.interpreter.subproject, location=self.current_node)
        return script_args

    @typed_pos_args(
        'meson.add_install_script',
        (str, mesonlib.File, build.Executable, ExternalProgram),
        varargs=(str, mesonlib.File, build.BuildTarget, build.CustomTarget, build.CustomTargetIndex, ExternalProgram)
    )
    @typed_kwargs(
        'meson.add_install_script',
        KwargInfo('skip_if_destdir', bool, default=False, since='0.57.0'),
        KwargInfo('install_tag', (str, NoneType), since='0.60.0'),
        KwargInfo('dry_run', bool, default=False, since='1.1.0'),
    )
    def add_install_script_method(
            self,
            args: T.Tuple[T.Union[str, mesonlib.File, build.Executable, ExternalProgram],
                          T.List[T.Union[str, mesonlib.File, build.BuildTarget, build.CustomTarget, build.CustomTargetIndex, ExternalProgram]]],
            kwargs: 'AddInstallScriptKW') -> None:
        script_args = self._process_script_args('add_install_script', args[1])
        script = self._find_source_script('add_install_script', args[0], script_args)
        script.skip_if_destdir = kwargs['skip_if_destdir']
        script.tag = kwargs['install_tag']
        script.dry_run = kwargs['dry_run']
        self.build.install_scripts.append(script)

    @typed_pos_args(
        'meson.add_postconf_script',
        (str, mesonlib.File, ExternalProgram),
        varargs=(str, mesonlib.File, ExternalProgram)
    )
    @noKwargs
    def add_postconf_script_method(
            self,
            args: T.Tuple[T.Union[str, mesonlib.File, ExternalProgram],
                          T.List[T.Union[str, mesonlib.File, ExternalProgram]]],
            kwargs: 'TYPE_kwargs') -> None:
        script_args = self._process_script_args('add_postconf_script', args[1])
        script = self._find_source_script('add_postconf_script', args[0], script_args)
        self.build.postconf_scripts.append(script)

    @typed_pos_args(
        'meson.add_dist_script',
        (str, mesonlib.File, ExternalProgram),
        varargs=(str, mesonlib.File, ExternalProgram)
    )
    @noKwargs
    @FeatureNew('meson.add_dist_script', '0.48.0')
    def add_dist_script_method(
            self,
            args: T.Tuple[T.Union[str, mesonlib.File, ExternalProgram],
                          T.List[T.Union[str, mesonlib.File, ExternalProgram]]],
            kwargs: 'TYPE_kwargs') -> None:
        if args[1]:
            FeatureNew.single_use('Calling "add_dist_script" with multiple arguments',
                                  '0.49.0', self.interpreter.subproject, location=self.current_node)
        if self.interpreter.subproject != '':
            FeatureNew.single_use('Calling "add_dist_script" in a subproject',
                                  '0.58.0', self.interpreter.subproject, location=self.current_node)
        script_args = self._process_script_args('add_dist_script', args[1])
        script = self._find_source_script('add_dist_script', args[0], script_args)
        self.build.dist_scripts.append(script)

    @noPosargs
    @noKwargs
    def current_source_dir_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        src = self.interpreter.environment.source_dir
        sub = self.interpreter.subdir
        if sub == '':
            return src
        return os.path.join(src, sub)

    @noPosargs
    @noKwargs
    def current_build_dir_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        sub = self.interpreter.subdir
        if sub == '':
            return self.interpreter.environment.build_dir
        return self.interpreter.absolute_builddir_path_for(sub)

    @noPosargs
    @noKwargs
    def backend_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.interpreter.backend.name

    @noPosargs
    @noKwargs
    @FeatureDeprecated('meson.source_root', '0.56.0', 'use meson.project_source_root() or meson.global_source_root() instead.')
    def source_root_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.interpreter.environment.source_dir

    @noPosargs
    @noKwargs
    @FeatureDeprecated('meson.build_root', '0.56.0', 'use meson.project_build_root() or meson.global_build_root() instead.')
    def build_root_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.interpreter.environment.build_dir

    @noPosargs
    @noKwargs
    @FeatureNew('meson.project_source_root', '0.56.0')
    def project_source_root_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        src = self.interpreter.environment.source_dir
        sub = self.interpreter.root_subdir
        if sub == '':
            return src
        return os.path.join(src, sub)

    @noPosargs
    @noKwargs
    @FeatureNew('meson.project_build_root', '0.56.0')
    def project_build_root_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        src = self.interpreter.environment.build_dir
        sub = self.interpreter.root_subdir
        if sub == '':
            return src
        return os.path.join(src, sub)

    @noPosargs
    @noKwargs
    @FeatureNew('meson.global_source_root', '0.58.0')
    def global_source_root_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.interpreter.environment.source_dir

    @noPosargs
    @noKwargs
    @FeatureNew('meson.global_build_root', '0.58.0')
    def global_build_root_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.interpreter.environment.build_dir

    @noPosargs
    @noKwargs
    @FeatureDeprecated('meson.has_exe_wrapper', '0.55.0', 'use meson.can_run_host_binaries instead.')
    def has_exe_wrapper_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> bool:
        return self._can_run_host_binaries_impl()

    @noPosargs
    @noKwargs
    @FeatureNew('meson.can_run_host_binaries', '0.55.0')
    def can_run_host_binaries_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> bool:
        return self._can_run_host_binaries_impl()

    def _can_run_host_binaries_impl(self) -> bool:
        return not (
            self.build.environment.is_cross_build() and
            self.build.environment.need_exe_wrapper() and
            self.build.environment.exe_wrapper is None
        )

    @noPosargs
    @noKwargs
    def is_cross_build_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> bool:
        return self.build.environment.is_cross_build()

    @typed_pos_args('meson.get_compiler', str)
    @typed_kwargs('meson.get_compiler', NATIVE_KW)
    def get_compiler_method(self, args: T.Tuple[str], kwargs: 'NativeKW') -> 'Compiler':
        cname = args[0]
        for_machine = kwargs['native']
        clist = self.interpreter.coredata.compilers[for_machine]
        try:
            return clist[cname]
        except KeyError:
            raise InterpreterException(f'Tried to access compiler for language "{cname}", not specified for {for_machine.get_lower_case_name()} machine.')

    @noPosargs
    @noKwargs
    def is_unity_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> bool:
        optval = self.interpreter.environment.coredata.get_option(OptionKey('unity'))
        return optval == 'on' or (optval == 'subprojects' and self.interpreter.is_subproject())

    @noPosargs
    @noKwargs
    def is_subproject_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> bool:
        return self.interpreter.is_subproject()

    @typed_pos_args('meson.install_dependency_manifest', str)
    @noKwargs
    def install_dependency_manifest_method(self, args: T.Tuple[str], kwargs: 'TYPE_kwargs') -> None:
        self.build.dep_manifest_name = args[0]

    @FeatureNew('meson.override_find_program', '0.46.0')
    @typed_pos_args('meson.override_find_program', str, (mesonlib.File, ExternalProgram, build.Executable))
    @typed_kwargs('meson.override_find_program', NATIVE_KW.evolve(since='1.3.0'))
    def override_find_program_method(self, args: T.Tuple[str, T.Union[mesonlib.File, ExternalProgram, build.Executable]], kwargs: NativeKW) -> None:
        name, exe = args
        if isinstance(exe, mesonlib.File):
            abspath = exe.absolute_path(self.interpreter.environment.source_dir,
                                        self.interpreter.environment.build_dir)
            if not os.path.exists(abspath):
                raise InterpreterException(f'Tried to override {name} with a file that does not exist.')
            exe = OverrideProgram(name, [abspath])
        self.interpreter.add_find_program_override(name, exe, kwargs['native'])

    @typed_kwargs(
        'meson.override_dependency',
        NATIVE_KW,
        KwargInfo('static', (bool, NoneType), since='0.60.0'),
    )
    @typed_pos_args('meson.override_dependency', str, dependencies.Dependency)
    @FeatureNew('meson.override_dependency', '0.54.0')
    def override_dependency_method(self, args: T.Tuple[str, dependencies.Dependency], kwargs: 'FuncOverrideDependency') -> None:
        name, dep = args
        if not name:
            raise InterpreterException('First argument must be a string and cannot be empty')

        # Make a copy since we're going to mutate.
        #
        #   dep = declare_dependency()
        #   meson.override_dependency('foo', dep)
        #   meson.override_dependency('foo-1.0', dep)
        #   dep = dependency('foo')
        #   dep.name() # == 'foo-1.0'
        dep = copy.copy(dep)
        dep.name = name

        optkey = OptionKey('default_library', subproject=self.interpreter.subproject)
        default_library = self.interpreter.coredata.get_option(optkey)
        assert isinstance(default_library, str), 'for mypy'
        static = kwargs['static']
        if static is None:
            # We don't know if dep represents a static or shared library, could
            # be a mix of both. We assume it is following default_library
            # value.
            self._override_dependency_impl(name, dep, kwargs, static=None)
            if default_library == 'static':
                self._override_dependency_impl(name, dep, kwargs, static=True)
            elif default_library == 'shared':
                self._override_dependency_impl(name, dep, kwargs, static=False)
            else:
                self._override_dependency_impl(name, dep, kwargs, static=True)
                self._override_dependency_impl(name, dep, kwargs, static=False)
        else:
            # dependency('foo') without specifying static kwarg should find this
            # override regardless of the static value here. But do not raise error
            # if it has already been overridden, which would happen when overriding
            # static and shared separately:
            # meson.override_dependency('foo', shared_dep, static: false)
            # meson.override_dependency('foo', static_dep, static: true)
            # In that case dependency('foo') would return the first override.
            self._override_dependency_impl(name, dep, kwargs, static=None, permissive=True)
            self._override_dependency_impl(name, dep, kwargs, static=static)

    def _override_dependency_impl(self, name: str, dep: dependencies.Dependency, kwargs: 'FuncOverrideDependency',
                                  static: T.Optional[bool], permissive: bool = False) -> None:
        # We need the cast here as get_dep_identifier works on such a dict,
        # which FuncOverrideDependency is, but mypy can't figure that out
        nkwargs = T.cast('T.Dict[str, T.Any]', kwargs.copy())
        if static is None:
            del nkwargs['static']
        else:
            nkwargs['static'] = static
        identifier = dependencies.get_dep_identifier(name, nkwargs)
        for_machine = kwargs['native']
        override = self.build.dependency_overrides[for_machine].get(identifier)
        if override:
            if permissive:
                return
            m = 'Tried to override dependency {!r} which has already been resolved or overridden at {}'
            location = mlog.get_error_location_string(override.node.filename, override.node.lineno)
            raise InterpreterException(m.format(name, location))
        self.build.dependency_overrides[for_machine][identifier] = \
            build.DependencyOverride(dep, self.interpreter.current_node)

    @noPosargs
    @noKwargs
    def project_version_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.build.dep_manifest[self.interpreter.active_projectname].version

    @FeatureNew('meson.project_license()', '0.45.0')
    @noPosargs
    @noKwargs
    def project_license_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> T.List[str]:
        return self.build.dep_manifest[self.interpreter.active_projectname].license

    @FeatureNew('meson.project_license_files()', '1.1.0')
    @noPosargs
    @noKwargs
    def project_license_files_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> T.List[mesonlib.File]:
        return [l[1] for l in self.build.dep_manifest[self.interpreter.active_projectname].license_files]

    @noPosargs
    @noKwargs
    def version_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> MesonVersionString:
        return MesonVersionString(self.interpreter.coredata.version)

    @noPosargs
    @noKwargs
    def project_name_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.interpreter.active_projectname

    def __get_external_property_impl(self, propname: str, fallback: T.Optional[object], machine: MachineChoice) -> object:
        """Shared implementation for get_cross_property and get_external_property."""
        try:
            return self.interpreter.environment.properties[machine][propname]
        except KeyError:
            if fallback is not None:
                return fallback
            raise InterpreterException(f'Unknown property for {machine.get_lower_case_name()} machine: {propname}')

    @noArgsFlattening
    @FeatureDeprecated('meson.get_cross_property', '0.58.0', 'Use meson.get_external_property() instead')
    @typed_pos_args('meson.get_cross_property', str, optargs=[object])
    @noKwargs
    def get_cross_property_method(self, args: T.Tuple[str, T.Optional[object]], kwargs: 'TYPE_kwargs') -> object:
        propname, fallback = args
        return self.__get_external_property_impl(propname, fallback, MachineChoice.HOST)

    @noArgsFlattening
    @FeatureNew('meson.get_external_property', '0.54.0')
    @typed_pos_args('meson.get_external_property', str, optargs=[object])
    @typed_kwargs('meson.get_external_property', NATIVE_KW)
    def get_external_property_method(self, args: T.Tuple[str, T.Optional[object]], kwargs: 'NativeKW') -> object:
        propname, fallback = args
        return self.__get_external_property_impl(propname, fallback, kwargs['native'])

    @FeatureNew('meson.has_external_property', '0.58.0')
    @typed_pos_args('meson.has_external_property', str)
    @typed_kwargs('meson.has_external_property', NATIVE_KW)
    def has_external_property_method(self, args: T.Tuple[str], kwargs: 'NativeKW') -> bool:
        prop_name = args[0]
        return prop_name in self.interpreter.environment.properties[kwargs['native']]

    @FeatureNew('add_devenv', '0.58.0')
    @typed_kwargs('environment', ENV_METHOD_KW, ENV_SEPARATOR_KW.evolve(since='0.62.0'))
    @typed_pos_args('add_devenv', (str, list, dict, mesonlib.EnvironmentVariables))
    def add_devenv_method(self, args: T.Tuple[T.Union[str, list, dict, mesonlib.EnvironmentVariables]],
                          kwargs: 'AddDevenvKW') -> None:
        env = args[0]
        msg = ENV_KW.validator(env)
        if msg:
            raise build.InvalidArguments(f'"add_devenv": {msg}')
        converted = env_convertor_with_method(env, kwargs['method'], kwargs['separator'])
        assert isinstance(converted, mesonlib.EnvironmentVariables)
        self.build.devenv.append(converted)

    @noPosargs
    @noKwargs
    @FeatureNew('meson.build_options', '1.1.0')
    def build_options_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        options = self.interpreter.user_defined_options
        if options is None:
            return ''
        return coredata.format_cmd_line_options(options)
```