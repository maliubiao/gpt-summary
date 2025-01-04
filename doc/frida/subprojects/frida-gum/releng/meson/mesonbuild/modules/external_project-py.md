Response:
Let's break down the thought process for analyzing this Python code and generating the detailed explanation.

**1. Understanding the Core Purpose:**

The first step is to read the initial comments and the overall structure of the file. The filename `external_project.py` and the class name `ExternalProjectModule` immediately suggest that this module is designed to handle external software projects within the Meson build system. The `frida` directory path provides context – this is part of the Frida dynamic instrumentation tool's build process.

**2. Deconstructing the Code - Class by Class:**

The code is well-organized into two main classes: `ExternalProject` and `ExternalProjectModule`. It's natural to analyze them separately.

* **`ExternalProject`:**
    * **Initialization (`__init__`)**: This is where the core configuration happens. Keywords like `configure_command`, `configure_options`, `cross_configure_options`, `env`, and `verbose` point to the crucial aspects of configuring an external project. The code deals with setting up directories (`src_dir`, `build_dir`, `install_dir`) and handling prefixes. The `_configure` method is called, suggesting that actual configuration logic resides there. The `_create_targets` method indicates how this external project integrates with Meson's build targets.
    * **`_configure`:** This method is responsible for running the external project's configuration script (like `configure`, `autogen.sh`, or even `waf`). It handles different configuration systems, setting environment variables (like `CFLAGS`, `LDFLAGS`), and logging.
    * **`_validate_configure_options` and `_format_options`:** These methods are about ensuring that necessary variables (like `prefix`, `libdir`) are passed to the configuration script.
    * **`_run`:** This is a utility function to execute shell commands, handling logging and error checking.
    * **`_create_targets`:** This is where the external project gets integrated into Meson's build graph as a `CustomTarget`. It defines the commands to build the external project. The creation of an `InstallDir` suggests how the output of the external project is installed.
    * **`dependency_method`:** This method is key for other Meson projects to use the built external project as a dependency. It provides necessary compiler and linker flags.

* **`ExternalProjectModule`:**
    * **Initialization:** This sets up the module within the Meson interpreter.
    * **`add_project`:** This is the main function that users call in their `meson.build` file to define an external project. It instantiates the `ExternalProject` class.

**3. Identifying Key Features and Relationships:**

After analyzing the classes, I started to connect the dots and identify the main functionalities:

* **External Project Integration:** The core function is to bring external projects (using Autotools, Make, Waf, or custom scripts) into the Meson build system.
* **Configuration Handling:**  The module deals with running the external project's configuration step, passing options, and managing environment variables.
* **Build Process:** It defines how the external project is built using `make` or a similar command.
* **Dependency Management:**  It allows other parts of the Meson project to depend on the output of the external project.
* **Installation:**  It manages the installation of the external project's output.

**4. Connecting to Reverse Engineering Concepts:**

This requires thinking about how Frida and similar tools are used. Frida is for dynamic instrumentation, often involving hooking into running processes. Therefore, being able to build external components that Frida might rely on is crucial. Examples include:

* **Building custom gadgets or agents:**  These might be separate projects that Frida needs.
* **Integrating with native libraries:** External projects might provide libraries that Frida interacts with.

**5. Identifying Low-Level/Kernel/Framework Aspects:**

Given Frida's nature, the interaction with low-level system components is expected. This is reflected in:

* **Handling of prefixes, libdirs, includedirs:** These are fundamental to how software is organized on Linux and other systems.
* **Setting compiler and linker flags (`CFLAGS`, `LDFLAGS`):** This directly relates to compiling and linking native code.
* **Cross-compilation support (`cross_configure_options`):**  Important for targeting different architectures (e.g., building Android components from a Linux host).

**6. Looking for Logic and Assumptions:**

* **Configuration Script Assumption:** The code assumes a configuration script exists in the source directory.
* **Make Assumption:** It defaults to using `make` for building unless Waf is specified.
* **Environment Variable Handling:**  The code explicitly manages environment variables for the configuration and build steps.

**7. Considering User Errors:**

This requires anticipating how a user might misuse the module:

* **Incorrect `configure_command`:** Specifying a non-existent or incorrect configuration script.
* **Missing dependencies:** The external project might require dependencies not explicitly handled.
* **Incorrect configuration options:**  Passing options that the external project doesn't understand.
* **Environment issues:**  Not setting up the required environment variables.

**8. Tracing User Interaction (Debugging Clues):**

This involves thinking about the steps a user would take when using this module within a `meson.build` file:

1. Adding the `external_project` module to their project.
2. Calling `external_project.add_project()` with the necessary arguments.
3. If something goes wrong, Meson will likely throw an error during the configuration or build step. The logs generated by `_run` would be crucial for debugging.

**9. Structuring the Explanation:**

Finally, organize the information into a clear and logical structure, using headings, bullet points, and code examples to illustrate the concepts. Start with a high-level overview and then delve into the details. Provide concrete examples to make the explanation more accessible.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe it just runs shell commands.
* **Correction:**  It's more sophisticated, managing configuration, dependencies, and integration into the Meson build graph.
* **Initial thought:**  Focus only on the code's actions.
* **Refinement:** Connect the code's actions to the broader concepts of reverse engineering, low-level programming, and potential user errors.
* **Initial thought:**  Keep explanations very technical.
* **Refinement:** Balance technical details with clear examples and explanations of the purpose of each part.

By following this structured thought process, breaking down the code into manageable parts, and connecting it to the broader context, I could generate a comprehensive and informative explanation of the provided Python code.
这是 Frida 动态 instrumentation 工具中负责处理外部项目的 Meson 模块的源代码文件。它的主要功能是允许将使用其他构建系统（如 Autotools 的 `configure` 脚本，或者 `make`，或者 Waf）的项目集成到基于 Meson 的 Frida 构建系统中。

以下是该文件的功能列表及其与逆向、底层知识、逻辑推理和常见错误的关系：

**功能列表:**

1. **定义 `ExternalProject` 类:**  封装了外部项目的相关信息和操作。
2. **配置外部项目:**
   - 确定配置命令 (`configure_command`)，例如 `configure` 脚本或 `waf configure`。
   - 传递配置选项 (`configure_options`) 和交叉编译配置选项 (`cross_configure_options`) 给外部项目。
   - 设置外部项目的环境变量 (`env`)，包括编译器、链接器标志等。
   - 执行配置命令，生成外部项目的构建文件。
3. **创建构建目标 (`_create_targets`):**
   - 在 Meson 中创建一个自定义构建目标 (`CustomTarget`)，用于触发外部项目的构建过程。
   - 使用 `make` 命令（或其他指定的构建命令）来构建外部项目。
   - 定义输出文件和依赖关系。
   - 创建安装目录 (`InstallDir`)，指定外部项目的安装位置。
4. **提供依赖项 (`dependency_method`):**
   - 允许其他 Meson 目标声明对该外部项目的依赖。
   - 返回一个 `InternalDependency` 对象，包含外部项目的头文件路径、库文件路径和链接选项。
5. **定义 `ExternalProjectModule` 类:**  作为 Meson 的扩展模块，提供 `add_project` 方法。
6. **添加外部项目 (`add_project`):**
   - 允许用户在 `meson.build` 文件中定义一个外部项目。
   - 接收外部项目的配置命令和选项。
   - 创建 `ExternalProject` 实例并将其添加到构建系统中。
7. **日志记录和错误处理:**
   - 记录配置和构建过程的日志。
   - 在配置或构建失败时抛出异常。

**与逆向方法的关系:**

* **集成第三方库:** 逆向工程常常需要使用各种工具和库。这个模块可以用来集成一些不是用 Meson 构建的第三方库，例如用于反汇编、模拟执行或者解包的库。
    * **举例:** 假设你需要集成一个用 Autotools 构建的反汇编引擎到 Frida 中。你可以使用 `external_project.add_project` 来运行该引擎的 `configure` 脚本并构建它，然后使用 `external_project.dependency` 将其库文件链接到 Frida 的某个组件中。
* **构建目标环境:** 有时，逆向分析需要在特定的目标环境下进行。该模块可以用于构建一些在目标系统上运行的工具或库，这些工具可能不是 Frida 的核心部分，但对逆向分析很有用。
    * **举例:** 你可能需要在 Android 设备上运行一个特定的 hook 框架的预编译版本。你可以创建一个外部项目来解压并安装这个框架到 Frida 的构建输出中。

**涉及二进制底层、Linux、Android 内核及框架的知识:**

* **编译器和链接器标志 (`CFLAGS`, `LDFLAGS`):** 该模块需要设置正确的编译器和链接器标志，这涉及到对二进制文件格式、ABI (Application Binary Interface) 以及链接过程的理解。这些知识对于在不同的平台（例如 Linux 和 Android）上正确构建二进制文件至关重要。
    * **举例:** 在交叉编译 Android 平台的 Frida 组件时，需要设置 Android NDK 提供的交叉编译工具链，并通过 `CFLAGS` 和 `LDFLAGS` 指定目标架构的头文件和库文件路径。
* **构建系统 (Autotools, Make, Waf):** 该模块需要能够处理不同构建系统的项目，需要了解这些构建系统的工作原理，例如 `configure` 脚本的作用、Makefile 的语法、Waf 的配置方式等。
* **文件系统路径 (PREFIX, LIBDIR, INCLUDEDIR):**  模块中涉及到设置安装路径，这需要了解 Linux 和 Android 文件系统的组织结构，例如标准库、头文件的存放位置。
    * **举例:**  在 Android 中，共享库通常位于 `/system/lib` 或 `/vendor/lib`，头文件可能在 NDK 的 `sysroot` 目录下。该模块需要能够将外部项目构建的库文件安装到 Frida 的输出目录中，以便 Frida 能够加载它们。
* **交叉编译:**  该模块支持交叉编译，这需要理解交叉编译的概念，即在一个平台上构建在另一个平台上运行的代码。这通常涉及到使用特定的交叉编译工具链和设置目标平台的系统信息。
    * **举例:** 从 Linux 主机构建运行在 Android 设备上的 Frida 组件就需要进行交叉编译。`cross_configure_options` 可以用来向外部项目的配置脚本传递目标平台的信息，例如 `--host=arm-linux-androideabi`。
* **环境变量:** 模块会设置和使用环境变量，这在 Linux 和 Android 环境中非常重要，用于指定编译器路径、库文件路径等。

**逻辑推理（假设输入与输出）:**

假设你在 `meson.build` 文件中添加了以下代码来集成一个名为 `mylib` 的外部项目，该项目使用 Autotools 构建：

```python
ext_proj = import('external_project')

mylib_dep = ext_proj.add_project(
  './configure', # 假设 configure 脚本在当前子项目目录下
  configure_options : [
    '--prefix=' + meson.build_root() + '/_install/mylib',
    '--enable-shared',
    '--disable-static'
  ],
  cross_configure_options : [
    '--host=' + host_machine.cpu_family() + '-linux-gnu' # 假设是 Linux 交叉编译
  ],
  depends : [] # 假设没有其他依赖
)

mylib = mylib_dep.get_default_object() # 获取构建目标
mylib_dep_obj = ext_proj.dependency('mylib') # 获取依赖对象
```

**假设输入:**

* 当前位于 Frida 项目的 `frida/subprojects/some_feature` 目录下。
* `mylib` 的源代码位于 `frida/subprojects/some_feature/mylib`。
* `frida/subprojects/some_feature/mylib` 目录下有 `configure` 脚本。
* 目标平台是 Linux。

**预期输出:**

1. Meson 会在构建目录下的 `frida/subprojects/some_feature/build` 目录中创建一个用于 `mylib` 的子目录。
2. Meson 会执行 `frida/subprojects/some_feature/mylib/configure` 脚本，并传递 `--prefix=/path/to/frida/build/_install/mylib`, `--enable-shared`, `--disable-static`, 以及交叉编译选项 `--host=x86_64-linux-gnu` (假设你的主机是 x86_64) 等参数。
3. 如果配置成功，Meson 会执行 `make` 命令来构建 `mylib`。
4. 构建完成后，`mylib` 的共享库和头文件会被安装到 `frida/build/_install/mylib` 目录下。
5. `mylib_dep_obj` 会包含指向 `frida/build/_install/mylib/lib` 的库路径和指向 `frida/build/_install/mylib/include` 的头文件路径，以及链接 `mylib` 所需的 `-lmylib` 等选项。

**涉及用户或者编程常见的使用错误:**

1. **错误的配置命令路径:** 用户可能指定了错误的 `configure_command` 路径，导致 Meson 找不到配置脚本。
    * **举例:**  `ext_proj.add_project('configure')` 而 `configure` 脚本实际上位于 `./mylib/configure`。
2. **缺少必要的配置选项:** 外部项目可能需要特定的配置选项才能正确构建，用户可能忘记添加这些选项。
    * **举例:** 外部项目需要 `--with-openssl` 选项，但用户没有在 `configure_options` 中指定。
3. **交叉编译选项不正确:** 在进行交叉编译时，用户可能提供了错误的 `cross_configure_options`，导致外部项目配置失败。
    * **举例:**  为 Android 平台构建时，`--host` 参数可能设置不正确，与目标架构不匹配。
4. **依赖项缺失:**  外部项目可能依赖于其他库，但用户没有正确声明这些依赖关系，导致构建失败。
    * **举例:** 外部项目依赖 `zlib`，但用户没有安装 `zlib-devel` 包，或者没有在 Meson 中显式声明对 `zlib` 的依赖。
5. **环境变量配置错误:** 有些外部项目可能依赖于特定的环境变量。用户可能没有正确设置这些环境变量。
    * **举例:** 外部项目需要 `PYTHON_HOME` 环境变量，但用户没有设置。
6. **构建工具缺失:** 系统中可能没有安装外部项目所需的构建工具，例如 `make` 或 `waf`。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试在 Frida 中集成一个外部库:**  用户为了扩展 Frida 的功能，需要集成一个不是用 Meson 构建的第三方库。
2. **用户编辑 `meson.build` 文件:** 用户在 Frida 项目的某个子目录下的 `meson.build` 文件中，希望使用 `external_project` 模块来添加这个外部库。
3. **用户调用 `external_project.add_project()`:** 用户在 `meson.build` 文件中编写代码，调用 `external_project.add_project()` 函数，并提供必要的参数，例如配置脚本的路径、配置选项等。
4. **Meson 解析 `meson.build`:** 当用户运行 `meson` 命令配置构建系统时，Meson 会解析 `meson.build` 文件，并执行其中的 Python 代码。
5. **`ExternalProjectModule.add_project()` 被调用:**  Meson 遇到 `external_project.add_project()` 的调用时，会执行 `external_project.py` 文件中 `ExternalProjectModule` 类的 `add_project` 方法。
6. **`ExternalProject` 实例被创建:** `add_project` 方法会创建一个 `ExternalProject` 类的实例，并初始化其成员变量，例如配置命令、选项等。
7. **`ExternalProject._configure()` 被调用:**  `ExternalProject` 的初始化过程中会调用 `_configure` 方法，尝试执行外部项目的配置脚本。
8. **如果配置失败:**  `_configure` 方法中执行 `Popen_safe` 运行配置脚本后，如果返回非零的退出码，则会抛出 `MesonException`，并包含错误信息和日志文件路径，作为调试线索。用户可以查看日志文件以获取更详细的错误信息。
9. **如果配置成功:**  `_create_targets` 方法会被调用，创建 Meson 的构建目标，用于后续的构建过程。

**作为调试线索，当用户遇到与外部项目集成相关的问题时，可以检查以下内容:**

* **`meson.build` 文件中的 `add_project` 调用:** 检查配置命令路径、配置选项、交叉编译选项是否正确。
* **查看 Meson 的配置和构建日志:**  日志文件会记录执行的命令及其输出，可以帮助定位配置或构建失败的原因。
* **检查外部项目的源代码和构建系统:** 确保外部项目的构建系统本身没有问题，所需的依赖项都已满足。
* **检查环境变量:**  确认是否需要设置特定的环境变量才能成功配置或构建外部项目。

总而言之，`external_project.py` 模块是 Frida 基于 Meson 的构建系统中一个关键的组成部分，它桥接了 Meson 构建系统和其他外部构建系统，使得集成第三方库和工具变得更加方便。这对于像 Frida 这样的复杂项目来说，是管理和扩展其功能的重要机制。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/external_project.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 The Meson development team

from __future__ import annotations

from pathlib import Path
import os
import shlex
import subprocess
import typing as T

from . import ExtensionModule, ModuleReturnValue, NewExtensionModule, ModuleInfo
from .. import mlog, build
from ..compilers.compilers import CFLAGS_MAPPING
from ..envconfig import ENV_VAR_PROG_MAP
from ..dependencies import InternalDependency
from ..dependencies.pkgconfig import PkgConfigInterface
from ..interpreterbase import FeatureNew
from ..interpreter.type_checking import ENV_KW, DEPENDS_KW
from ..interpreterbase.decorators import ContainerTypeInfo, KwargInfo, typed_kwargs, typed_pos_args
from ..mesonlib import (EnvironmentException, MesonException, Popen_safe, MachineChoice,
                        get_variable_regex, do_replacement, join_args, OptionKey)

if T.TYPE_CHECKING:
    from typing_extensions import TypedDict

    from . import ModuleState
    from .._typing import ImmutableListProtocol
    from ..build import BuildTarget, CustomTarget
    from ..interpreter import Interpreter
    from ..interpreterbase import TYPE_var
    from ..mesonlib import EnvironmentVariables
    from ..utils.core import EnvironOrDict

    class Dependency(TypedDict):

        subdir: str

    class AddProject(TypedDict):

        configure_options: T.List[str]
        cross_configure_options: T.List[str]
        verbose: bool
        env: EnvironmentVariables
        depends: T.List[T.Union[BuildTarget, CustomTarget]]


class ExternalProject(NewExtensionModule):

    make: ImmutableListProtocol[str]

    def __init__(self,
                 state: 'ModuleState',
                 configure_command: str,
                 configure_options: T.List[str],
                 cross_configure_options: T.List[str],
                 env: EnvironmentVariables,
                 verbose: bool,
                 extra_depends: T.List[T.Union['BuildTarget', 'CustomTarget']]):
        super().__init__()
        self.methods.update({'dependency': self.dependency_method,
                             })

        self.subdir = Path(state.subdir)
        self.project_version = state.project_version
        self.subproject = state.subproject
        self.env = state.environment
        self.configure_command = configure_command
        self.configure_options = configure_options
        self.cross_configure_options = cross_configure_options
        self.verbose = verbose
        self.user_env = env

        self.src_dir = Path(self.env.get_source_dir(), self.subdir)
        self.build_dir = Path(self.env.get_build_dir(), self.subdir, 'build')
        self.install_dir = Path(self.env.get_build_dir(), self.subdir, 'dist')
        _p = self.env.coredata.get_option(OptionKey('prefix'))
        assert isinstance(_p, str), 'for mypy'
        self.prefix = Path(_p)
        _l = self.env.coredata.get_option(OptionKey('libdir'))
        assert isinstance(_l, str), 'for mypy'
        self.libdir = Path(_l)
        _i = self.env.coredata.get_option(OptionKey('includedir'))
        assert isinstance(_i, str), 'for mypy'
        self.includedir = Path(_i)
        self.name = self.src_dir.name

        # On Windows if the prefix is "c:/foo" and DESTDIR is "c:/bar", `make`
        # will install files into "c:/bar/c:/foo" which is an invalid path.
        # Work around that issue by removing the drive from prefix.
        if self.prefix.drive:
            self.prefix = self.prefix.relative_to(self.prefix.drive)

        # self.prefix is an absolute path, so we cannot append it to another path.
        self.rel_prefix = self.prefix.relative_to(self.prefix.root)

        self._configure(state)

        self.targets = self._create_targets(extra_depends, state.is_build_only_subproject)

    def _configure(self, state: 'ModuleState') -> None:
        if self.configure_command == 'waf':
            FeatureNew('Waf external project', '0.60.0').use(self.subproject, state.current_node)
            waf = state.find_program('waf')
            configure_cmd = waf.get_command()
            configure_cmd += ['configure', '-o', str(self.build_dir)]
            workdir = self.src_dir
            self.make = waf.get_command() + ['build']
        else:
            # Assume it's the name of a script in source dir, like 'configure',
            # 'autogen.sh', etc).
            configure_path = Path(self.src_dir, self.configure_command)
            configure_prog = state.find_program(configure_path.as_posix())
            configure_cmd = configure_prog.get_command()
            workdir = self.build_dir
            self.make = state.find_program('make').get_command()

        d = [('PREFIX', '--prefix=@PREFIX@', self.prefix.as_posix()),
             ('LIBDIR', '--libdir=@PREFIX@/@LIBDIR@', self.libdir.as_posix()),
             ('INCLUDEDIR', None, self.includedir.as_posix()),
             ]
        self._validate_configure_options(d, state)

        configure_cmd += self._format_options(self.configure_options, d)

        if self.env.is_cross_build():
            host = '{}-{}-{}'.format(state.environment.machines.host.cpu,
                                     'pc' if state.environment.machines.host.cpu_family in {"x86", "x86_64"}
                                     else 'unknown',
                                     state.environment.machines.host.system)
            d = [('HOST', None, host)]
            configure_cmd += self._format_options(self.cross_configure_options, d)

        # Set common env variables like CFLAGS, CC, etc.
        link_exelist: T.List[str] = []
        link_args: T.List[str] = []
        self.run_env: EnvironOrDict = os.environ.copy()
        for lang, compiler in self.env.coredata.compilers[MachineChoice.HOST].items():
            if any(lang not in i for i in (ENV_VAR_PROG_MAP, CFLAGS_MAPPING)):
                continue
            cargs = self.env.coredata.get_external_args(MachineChoice.HOST, lang)
            assert isinstance(cargs, list), 'for mypy'
            self.run_env[ENV_VAR_PROG_MAP[lang]] = self._quote_and_join(compiler.get_exelist())
            self.run_env[CFLAGS_MAPPING[lang]] = self._quote_and_join(cargs)
            if not link_exelist:
                link_exelist = compiler.get_linker_exelist()
                _l = self.env.coredata.get_external_link_args(MachineChoice.HOST, lang)
                assert isinstance(_l, list), 'for mypy'
                link_args = _l
        if link_exelist:
            # FIXME: Do not pass linker because Meson uses CC as linker wrapper,
            # but autotools often expects the real linker (e.h. GNU ld).
            # self.run_env['LD'] = self._quote_and_join(link_exelist)
            pass
        self.run_env['LDFLAGS'] = self._quote_and_join(link_args)

        self.run_env = self.user_env.get_env(self.run_env)
        self.run_env = PkgConfigInterface.setup_env(self.run_env, self.env, MachineChoice.HOST,
                                                    uninstalled=True)

        self.build_dir.mkdir(parents=True, exist_ok=True)
        self._run('configure', configure_cmd, workdir)

    def _quote_and_join(self, array: T.List[str]) -> str:
        return ' '.join([shlex.quote(i) for i in array])

    def _validate_configure_options(self, variables: T.List[T.Tuple[str, str, str]], state: 'ModuleState') -> None:
        # Ensure the user at least try to pass basic info to the build system,
        # like the prefix, libdir, etc.
        for key, default, val in variables:
            if default is None:
                continue
            key_format = f'@{key}@'
            for option in self.configure_options:
                if key_format in option:
                    break
            else:
                FeatureNew('Default configure_option', '0.57.0').use(self.subproject, state.current_node)
                self.configure_options.append(default)

    def _format_options(self, options: T.List[str], variables: T.List[T.Tuple[str, str, str]]) -> T.List[str]:
        out: T.List[str] = []
        missing = set()
        regex = get_variable_regex('meson')
        confdata: T.Dict[str, T.Tuple[str, T.Optional[str]]] = {k: (v, None) for k, _, v in variables}
        for o in options:
            arg, missing_vars = do_replacement(regex, o, 'meson', confdata)
            missing.update(missing_vars)
            out.append(arg)
        if missing:
            var_list = ", ".join(repr(m) for m in sorted(missing))
            raise EnvironmentException(
                f"Variables {var_list} in configure options are missing.")
        return out

    def _run(self, step: str, command: T.List[str], workdir: Path) -> None:
        mlog.log(f'External project {self.name}:', mlog.bold(step))
        m = 'Running command ' + str(command) + ' in directory ' + str(workdir) + '\n'
        log_filename = Path(mlog.get_log_dir(), f'{self.name}-{step}.log')
        output = None
        if not self.verbose:
            output = open(log_filename, 'w', encoding='utf-8')
            output.write(m + '\n')
            output.flush()
        else:
            mlog.log(m)
        p, *_ = Popen_safe(command, cwd=workdir, env=self.run_env,
                           stderr=subprocess.STDOUT,
                           stdout=output)
        if p.returncode != 0:
            m = f'{step} step returned error code {p.returncode}.'
            if not self.verbose:
                m += '\nSee logs: ' + str(log_filename)
            raise MesonException(m)

    def _create_targets(self, extra_depends: T.List[T.Union['BuildTarget', 'CustomTarget']], is_build_only_subproject: bool) -> T.List['TYPE_var']:
        cmd = self.env.get_build_command()
        cmd += ['--internal', 'externalproject',
                '--name', self.name,
                '--srcdir', self.src_dir.as_posix(),
                '--builddir', self.build_dir.as_posix(),
                '--installdir', self.install_dir.as_posix(),
                '--logdir', mlog.get_log_dir(),
                '--make', join_args(self.make),
                ]
        if self.verbose:
            cmd.append('--verbose')

        self.target = build.CustomTarget(
            self.name,
            self.subdir.as_posix(),
            self.subproject,
            self.env,
            cmd + ['@OUTPUT@', '@DEPFILE@'],
            [],
            [f'{self.name}.stamp'],
            is_build_only_subproject,
            depfile=f'{self.name}.d',
            console=True,
            extra_depends=extra_depends,
            description='Generating external project {}',
        )

        idir = build.InstallDir(self.subdir.as_posix(),
                                Path('dist', self.rel_prefix).as_posix(),
                                install_dir='.',
                                install_dir_name='.',
                                install_mode=None,
                                exclude=None,
                                strip_directory=True,
                                from_source_dir=False,
                                subproject=self.subproject)

        return [self.target, idir]

    @typed_pos_args('external_project.dependency', str)
    @typed_kwargs('external_project.dependency', KwargInfo('subdir', str, default=''))
    def dependency_method(self, state: 'ModuleState', args: T.Tuple[str], kwargs: 'Dependency') -> InternalDependency:
        libname = args[0]

        abs_includedir = Path(self.install_dir, self.rel_prefix, self.includedir)
        if kwargs['subdir']:
            abs_includedir = Path(abs_includedir, kwargs['subdir'])
        abs_libdir = Path(self.install_dir, self.rel_prefix, self.libdir)

        version = self.project_version
        compile_args = [f'-I{abs_includedir}']
        link_args = [f'-L{abs_libdir}', f'-l{libname}']
        sources = self.target
        dep = InternalDependency(version, [], compile_args, link_args, [],
                                 [], [sources], [], [], {}, [], [], [])
        return dep


class ExternalProjectModule(ExtensionModule):

    INFO = ModuleInfo('External build system', '0.56.0', unstable=True)

    def __init__(self, interpreter: 'Interpreter'):
        super().__init__(interpreter)
        self.methods.update({'add_project': self.add_project,
                             })

    @typed_pos_args('external_project_mod.add_project', str)
    @typed_kwargs(
        'external_project.add_project',
        KwargInfo('configure_options', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo('cross_configure_options', ContainerTypeInfo(list, str), default=['--host=@HOST@'], listify=True),
        KwargInfo('verbose', bool, default=False),
        ENV_KW,
        DEPENDS_KW.evolve(since='0.63.0'),
    )
    def add_project(self, state: 'ModuleState', args: T.Tuple[str], kwargs: 'AddProject') -> ModuleReturnValue:
        configure_command = args[0]
        project = ExternalProject(state,
                                  configure_command,
                                  kwargs['configure_options'],
                                  kwargs['cross_configure_options'],
                                  kwargs['env'],
                                  kwargs['verbose'],
                                  kwargs['depends'])
        return ModuleReturnValue(project, project.targets)


def initialize(interp: 'Interpreter') -> ExternalProjectModule:
    return ExternalProjectModule(interp)

"""

```