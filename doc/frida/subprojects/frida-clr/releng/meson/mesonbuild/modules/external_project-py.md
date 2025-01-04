Response:
Let's break down the thought process for analyzing this Python code and answering the request.

**1. Understanding the Goal:**

The core goal is to understand the functionality of the provided Python script (`external_project.py`) within the context of the Frida dynamic instrumentation tool. Specifically, I need to identify its purpose, relate it to reverse engineering, and pinpoint its interactions with lower-level systems. The request also asks for examples of logic, user errors, and debugging steps.

**2. Initial Code Scan and High-Level Understanding:**

The first step is a quick skim of the code to get a general idea of what it does. Keywords like "external_project," "configure," "make," "dependency," and "add_project" immediately stand out. The presence of `subprocess.Popen_safe` suggests it interacts with external build systems. The imports, like `os`, `shlex`, and `pathlib`, indicate file system and shell command manipulation.

From this initial scan, I can hypothesize that this module is responsible for integrating external projects (likely written in C/C++ or other compiled languages) into the Frida build process.

**3. Deeper Dive into Key Classes and Methods:**

I then focus on the main classes and their methods:

* **`ExternalProject`:** This seems to be the core class representing a single external project. I examine its `__init__` method to understand how an external project is initialized:  It takes configuration commands, options, environment variables, and dependencies. The `_configure` method deals with running the external project's configuration script (like `./configure` or `waf configure`). The `_create_targets` method generates Meson build targets for the external project. The `dependency_method` creates a Meson dependency object that other parts of the Frida build can use.

* **`ExternalProjectModule`:** This appears to be the Meson module that exposes the functionality to the Meson build system. The `add_project` method is the entry point for declaring an external project in the `meson.build` file.

**4. Connecting to Reverse Engineering:**

Now, I consider how this functionality relates to reverse engineering. Frida itself is a reverse engineering tool. Integrating external projects into Frida likely involves incorporating libraries or components that extend Frida's capabilities or support specific target environments. The `dependency_method` is a crucial link, as it allows Frida to link against the compiled output of these external projects.

* **Example:** I think about a scenario where Frida needs to interact with a custom protocol or file format. An external library implementing the parsing or handling of that format could be integrated using this module.

**5. Identifying Interactions with Low-Level Systems:**

I look for code that interacts with the operating system and build tools:

* **Binary/Low-Level:** The execution of external configure and make commands directly interacts with compiled binaries. The concept of linking libraries (through `link_args`) is fundamentally a low-level operation.
* **Linux:**  The script uses concepts common in Linux/Unix-like environments: `./configure`, `make`, environment variables (CFLAGS, LDFLAGS, etc.), and paths.
* **Android Kernel/Framework (Implicit):** While not explicitly mentioned in the code, the context of Frida strongly suggests this module *can* be used for integrating components relevant to Android reverse engineering. Frida is heavily used on Android. External projects could be libraries for interacting with Android's Binder IPC, ART runtime, or other framework components.

**6. Analyzing Logic and Assumptions:**

I examine the conditional statements and loops to understand the logic:

* **Configuration Logic:** The `_configure` method handles different configuration systems (like autotools and Waf) based on the `configure_command`. It also manages the passing of prefix, libdir, etc.
* **Environment Variable Handling:** The script carefully constructs environment variables (`self.run_env`) for the external project's build process. This involves combining Meson's configuration with user-provided environment variables.
* **Dependency Creation:**  The `dependency_method` builds an `InternalDependency` object, which is a structured way for Meson to represent dependencies between build targets.

* **Assumptions:** The code assumes the presence of `make` or `waf` executables in the system's PATH. It also makes assumptions about the standard layout of install directories (bin, lib, include).

**7. Brainstorming User Errors:**

I consider common mistakes users might make when using this module:

* **Incorrect `configure_command`:**  Specifying a non-existent or incorrect script name.
* **Missing Dependencies:** The external project might have its own dependencies that aren't installed.
* **Incorrect Options:**  Providing wrong or incompatible configure options.
* **Environment Issues:**  Not having the necessary tools (like compilers) in the PATH.

**8. Tracing User Operations and Debugging:**

I think about the steps a user would take to reach this code:

1. **Writing `meson.build`:**  The user would add an `external_project.add_project()` call in their `meson.build` file.
2. **Running Meson:** Executing the `meson` command would trigger the parsing and execution of the `meson.build` file, eventually leading to the invocation of `ExternalProjectModule.add_project`.
3. **Debugging:** If something goes wrong, the error messages from Meson (and the logs generated by `_run`) would be the primary debugging clues. Users might need to examine the generated build directory and the logs of the external project's configure and make processes.

**9. Structuring the Answer:**

Finally, I organize the information into the categories requested: functionality, relation to reverse engineering, low-level details, logic, user errors, and debugging. I provide concrete examples to illustrate each point. I also try to maintain a clear and concise writing style.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps this module directly *runs* the Frida instrumentation. **Correction:**  The code focuses on *building* and *integrating* external projects. Frida instrumentation happens at runtime.
* **Overly specific assumption:** I might initially focus too much on C/C++ projects. **Refinement:**  While likely common, the module is designed to handle *any* external project with a configuration and build process.
* **Missing nuance:** I might initially overlook the importance of environment variable management. **Correction:**  The code explicitly handles this, and it's crucial for cross-compilation and ensuring the external build uses the correct tools.

By following these steps, I can systematically analyze the code and generate a comprehensive and accurate answer to the user's request.
这个Python源代码文件 `external_project.py` 是 Frida 动态 instrumentation 工具中 Meson 构建系统的一个模块，专门用于集成外部项目到 Frida 的构建过程中。它允许 Frida 的构建系统调用外部的构建系统（例如 `configure` 脚本或 `make`）来构建第三方库或组件，并将它们集成到 Frida 的最终产品中。

以下是其功能点的详细说明：

**1. 集成外部构建系统:**

* **功能:** 该模块的核心功能是允许在 Frida 的构建过程中包含和构建外部项目。这意味着你可以依赖其他独立的库或工具，而无需将它们的源代码直接复制到 Frida 的源代码树中。
* **逆向方法关系:** 在逆向工程中，经常需要使用各种辅助工具和库。例如，可能需要集成一个用于解析特定文件格式的库，或者一个用于符号解析的工具。`external_project` 模块使得 Frida 能够灵活地集成这些外部依赖项，从而扩展 Frida 的功能，使其能够处理更广泛的逆向任务。
* **二进制底层知识:**  该模块需要理解外部构建系统（如 Autotools 的 `configure` 和 `make`）的工作原理，以及如何将编译好的库（通常是动态链接库 `.so` 或 `.dylib`，或者静态库 `.a`）链接到 Frida 的项目中。
* **Linux 知识:**  常见的外部项目构建过程通常依赖于 Linux/Unix 环境下的工具，例如 `configure` 脚本、`make` 命令，以及环境变量如 `PREFIX`、`LIBDIR`、`CFLAGS` 等。该模块需要处理这些概念。
* **逻辑推理:**
    * **假设输入:** 用户在 `meson.build` 文件中调用 `external_project.add_project()` 函数，指定了外部项目的配置命令（例如 "configure"）、配置选项、源代码目录等信息。
    * **输出:** 该模块会执行以下步骤：
        1. 在指定的构建目录下创建一个子目录用于外部项目的构建。
        2. 运行外部项目的配置命令，传递用户指定的配置选项以及一些默认选项（例如 `--prefix`，用于指定安装路径）。
        3. 运行 `make` 命令来构建外部项目。
        4. 创建 Meson 的 `CustomTarget`，表示这个外部项目的构建步骤。
        5. 提供 `dependency()` 方法，允许 Frida 的其他部分声明对这个外部项目构建产物的依赖。

**2. 配置外部项目:**

* **功能:**  该模块负责运行外部项目的配置脚本（例如 `configure`），并传递必要的配置选项。它还处理交叉编译的情况，为目标平台设置合适的配置选项。
* **逆向方法关系:** 在为不同的目标架构（例如 ARM Android）构建 Frida 时，需要使用交叉编译工具链。`external_project` 模块允许为外部项目传递交叉编译相关的配置选项，确保外部库能够正确地为目标平台构建。
* **二进制底层/Linux 知识:** 交叉编译需要理解不同架构的差异，例如指令集、ABI 等。配置选项中常见的如 `--host` 参数就是用于指定目标平台。
* **逻辑推理:**
    * **假设输入:**  用户指定了 `cross_configure_options`，例如 `--host=arm-linux-gnueabihf`。
    * **输出:**  在运行外部项目的配置脚本时，会将 `--host=arm-linux-gnueabihf` 添加到配置命令中。

**3. 构建外部项目:**

* **功能:**  运行 `make` 命令（或其他指定的构建命令）来构建外部项目。
* **逆向方法关系:**  这是将外部代码编译成可执行文件或库的关键步骤。逆向工程师通常需要构建他们依赖的工具和库。
* **二进制底层知识:**  构建过程涉及到编译器的调用、链接器的使用，最终生成二进制文件。
* **逻辑推理:**
    * **假设输入:**  外部项目的 `Makefile` 中定义了构建规则。
    * **输出:**  `make` 命令会按照 `Makefile` 的规则执行，编译源代码并生成目标文件和库文件。

**4. 创建 Meson 依赖:**

* **功能:**  提供 `dependency()` 方法，允许 Frida 的其他模块声明对外部项目构建产物的依赖。这使得 Meson 能够正确地管理构建顺序，确保在需要使用外部库之前，它已经被成功构建。
* **逆向方法关系:**  Frida 的不同组件可能依赖于外部库提供的功能。通过声明依赖，Meson 可以确保这些依赖关系得到满足。
* **逻辑推理:**
    * **假设输入:** Frida 的一个模块需要链接到外部项目构建的名为 "mylib" 的库。
    * **输出:** 该模块调用 `external_project_instance.dependency('mylib')`，Meson 会创建一个 `InternalDependency` 对象，其中包含了链接 "mylib" 所需的信息（例如库的路径、链接参数）。

**5. 处理环境变量:**

* **功能:**  该模块会设置外部项目构建所需的常用环境变量，例如 `CFLAGS`、`CC`、`LDFLAGS` 等。这确保了外部项目能够使用与 Frida 构建相同的编译器和编译选项。
* **逆向方法关系:**  确保外部库与 Frida 使用相同的编译环境可以避免潜在的兼容性问题。
* **Linux 知识:** 这些环境变量是 Linux/Unix 构建系统中常见的设置。
* **逻辑推理:**
    * **假设输入:** Frida 的构建配置指定了使用的 C 编译器是 `gcc`，并设置了一些 C 编译选项。
    * **输出:**  在运行外部项目的配置和构建命令时，会设置 `CC` 环境变量为 `gcc`，`CFLAGS` 环境变量为 Frida 指定的编译选项。

**6. 日志记录:**

* **功能:**  记录外部项目的配置和构建过程的输出，方便调试。
* **逆向方法关系:**  当外部项目的构建失败时，查看日志是定位问题的关键步骤。

**用户或编程常见的使用错误示例:**

1. **配置命令错误:** 用户在 `add_project()` 中指定的 `configure_command` 不存在或者路径错误。
   * **用户操作:** 在 `meson.build` 文件中错误地写成了 `configuree` 而不是 `configure`。
   * **到达这里:** Meson 执行到 `external_project.add_project()` 时，会尝试查找并执行指定的配置命令，如果找不到则会报错。

2. **配置选项错误:** 用户传递了外部项目不支持的配置选项。
   * **用户操作:**  为一个使用 Autotools 的项目传递了 Waf 特有的配置选项。
   * **到达这里:**  `_configure()` 方法会构建配置命令并执行，外部项目的配置脚本会解析这些选项，如果遇到不支持的选项可能会报错并退出，导致 `_run()` 方法抛出 `MesonException`。

3. **缺少依赖:** 外部项目依赖的其他库或工具没有安装。
   * **用户操作:**  集成的外部库依赖于 `zlib`，但系统上没有安装 `zlib-dev` 包。
   * **到达这里:**  外部项目的配置或构建过程会尝试找到 `zlib` 的头文件和库文件，如果找不到则会报错，同样会导致 `_run()` 抛出异常。

4. **环境变量冲突:** 用户自定义的环境变量与外部项目所需的冲突。
   * **用户操作:**  用户设置了错误的 `PATH` 环境变量，导致外部项目的构建工具找不到。
   * **到达这里:**  `_run()` 方法在执行外部命令时会使用当前的环境变量，如果环境变量设置不当，可能会导致外部命令执行失败。

5. **依赖声明错误:**  在 Frida 的其他模块中错误地声明了对外部项目的依赖，例如库名写错了。
   * **用户操作:**  调用 `dependency()` 时，提供的库名与外部项目实际生成的库名不符。
   * **到达这里:**  当 Frida 的其他模块尝试链接到该依赖时，链接器会找不到指定的库文件，导致链接错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **编写 `meson.build` 文件:**  用户首先需要在 Frida 项目的 `meson.build` 文件中添加对 `external_project` 模块的调用，使用 `external_project.add_project()` 函数来声明要集成的外部项目。这包括指定外部项目的源代码路径、配置命令、配置选项等。

2. **运行 Meson 构建命令:** 用户在 Frida 项目的根目录或构建目录下运行 `meson setup <builddir>` 来配置构建环境，或者运行 `meson compile -C <builddir>` 来开始构建。

3. **Meson 解析 `meson.build`:**  Meson 会解析 `meson.build` 文件，当遇到 `external_project.add_project()` 调用时，会创建 `ExternalProject` 类的实例。

4. **执行外部项目的配置:** `ExternalProject` 类的 `_configure()` 方法会被调用，该方法会构建并执行外部项目的配置命令。

5. **执行外部项目的构建:**  `ExternalProject` 类的 `_create_targets()` 方法会创建一个 `CustomTarget`，表示外部项目的构建步骤。当 Meson 执行到这个 target 时，会调用 `make` 命令来构建外部项目。

6. **声明和使用依赖:** Frida 的其他模块可以使用 `external_project_instance.dependency()` 方法来声明对外部项目的依赖。

**调试线索:**

* **Meson 的输出:** Meson 在执行构建过程中会输出信息，包括执行的命令、错误信息等。查看这些输出可以帮助定位问题。
* **外部项目的日志:** `_run()` 方法会将外部项目的配置和构建输出记录到日志文件中（例如 `<builddir>/meson-logs/<project_name>-configure.log` 和 `<project_name>-build.log`）。查看这些日志是调试外部项目构建问题的关键。
* **检查 `meson.build` 文件:** 仔细检查 `meson.build` 文件中 `external_project.add_project()` 的参数是否正确，例如源代码路径、配置命令、配置选项等。
* **手动执行外部命令:**  可以尝试手动在命令行中执行外部项目的配置和构建命令，以隔离问题是否出在 Meson 集成部分还是外部项目本身。
* **查看环境变量:** 检查 Meson 设置的环境变量是否正确传递给了外部项目的构建过程。

总而言之，`external_project.py` 模块是 Frida 构建系统中一个非常重要的组件，它桥接了 Frida 的构建系统和外部项目的构建系统，使得 Frida 能够灵活地集成第三方代码，扩展其功能，这对于需要利用各种外部工具和库的逆向工程场景至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/modules/external_project.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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