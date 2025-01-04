Response:
Let's break down the thought process to analyze this Python code for the Frida project.

**1. Initial Understanding - What is this code doing?**

The first lines tell us this is part of Frida, specifically the `frida-qml` subproject, and deals with `external_project.py`. The header also mentions "Meson," a build system. This immediately suggests that this code is about integrating external projects (likely written with other build systems like Autotools, Make, or Waf) into a Meson-based build.

**2. Deconstructing the Class Structure:**

The code defines two main classes: `ExternalProject` and `ExternalProjectModule`. It's often helpful to start with the module class.

*   **`ExternalProjectModule`:** This seems like the entry point from the Meson build files. It has a method `add_project`. This strongly suggests that a user in a Meson build file will call something like `external_project.add_project(...)` to incorporate an external project.

*   **`ExternalProject`:** This class seems to encapsulate the details of a single external project. It handles configuration, building, and installation of that external project. Key methods like `_configure`, `_create_targets`, and `dependency_method` point to different stages of this process.

**3. Analyzing Key Methods and Attributes:**

Now, dive into the important parts of each class.

*   **`ExternalProject.__init__`:**  This is the constructor. It takes a lot of parameters, which gives hints about what information is needed to define an external project: source directory, build directory, configure options, environment variables, and dependencies. The initialization of paths (like `src_dir`, `build_dir`, `install_dir`) is crucial.

*   **`ExternalProject._configure`:** This method is responsible for running the external project's configuration script (like `configure` or `waf configure`). It handles setting up environment variables and passing configuration options. The logic for handling 'waf' vs. other configure scripts is a key detail. The code also attempts to pass standard variables like `PREFIX`, `LIBDIR`, and `INCLUDEDIR`.

*   **`ExternalProject._create_targets`:** This method creates a Meson `CustomTarget`. This is how the external project's build process gets integrated into the overall Meson build. The command it builds contains `--internal externalproject`, suggesting an internal Meson mechanism for handling this.

*   **`ExternalProject.dependency_method`:** This is how other parts of the Meson build can depend on the libraries built by the external project. It creates an `InternalDependency` object with the necessary include directories and link arguments.

*   **`ExternalProjectModule.add_project`:**  This is the user-facing method. It takes the configuration command and options, creates an `ExternalProject` instance, and returns a `ModuleReturnValue` containing the targets.

**4. Connecting to the Prompt's Requirements:**

Now, systematically address each point in the prompt:

*   **Functionality:** Summarize what the code does based on the analysis so far. It integrates external build systems into Meson.

*   **Relationship to Reverse Engineering:**  Think about *why* you'd integrate an external project in Frida. Frida is about dynamic instrumentation. External libraries might provide low-level access, parsing capabilities, or other functionalities needed for instrumentation. Specifically mention how this helps integrate components that might be written in C/C++ and require compilation.

*   **Binary/Kernel/Framework Knowledge:** Look for keywords and actions that relate to these areas. The passing of `CFLAGS`, `LDFLAGS`, and environment variables for compilers and linkers clearly points to binary concerns. The mentioning of Linux and Android (through the host architecture detection) and concepts like `prefix`, `libdir`, and `includedir` are relevant.

*   **Logical Inference (Hypothetical Input/Output):**  Imagine a simple scenario. What would a user type in a `meson.build` file? What would be the resulting Meson target? Show the call to `external_project.add_project` and the likely generated custom target command.

*   **Common Usage Errors:** Consider what could go wrong. Incorrect paths, missing dependencies, wrong configure options, and environment issues are likely candidates. Provide specific examples.

*   **User Operations and Debugging:**  Trace the user's actions. They edit `meson.build`, run Meson, and then the external project's configuration and build happen. Explain how the log files mentioned in the code (`{self.name}-{step}.log`) would be crucial for debugging.

**5. Refining and Structuring the Answer:**

Organize the findings clearly under each of the prompt's points. Use bullet points, code snippets, and clear explanations. Ensure the language is precise and avoids jargon where possible, or explains it when necessary. Review the answer to make sure it's comprehensive and accurate.

**Self-Correction/Refinement During the Process:**

*   **Initial Thought:**  Maybe this is just about downloading and unpacking external archives.
*   **Correction:** The presence of `configure_command`, `configure_options`, and `make` strongly indicates the execution of external build systems, not just archive handling.

*   **Initial Thought:**  Focus heavily on the Python syntax.
*   **Correction:** While syntax is important, the core of the analysis should be about the *purpose* and *functionality* within the context of Frida and Meson.

*   **Initial Thought:**  Assume deep knowledge of Meson internals.
*   **Correction:** Explain Meson concepts like `CustomTarget` briefly for someone who might not be a Meson expert.

By following this structured approach, breaking down the code, and systematically addressing the prompt's requirements, a comprehensive and accurate answer can be constructed.
这个Python源代码文件 `external_project.py` 是 Frida 动态 instrumentation工具中 Meson 构建系统的一个模块，其主要功能是**允许 Frida 的构建系统集成和管理外部的、非 Meson 构建的项目**。这意味着 Frida 可以依赖那些使用 Autotools (configure/make)，Waf，或其他构建系统的第三方库或组件。

下面是对其功能的详细列举，并根据你的要求进行说明：

**1. 功能列举:**

*   **定义外部项目:** 提供 `add_project` 方法，允许在 Meson 的 `meson.build` 文件中声明一个外部项目。这包括指定配置命令（如 `configure` 脚本或 `waf` 命令）、配置选项、交叉编译配置选项等。
*   **配置外部项目:**  负责执行外部项目的配置命令。它可以处理不同类型的配置系统，例如基于 `configure` 脚本的系统和基于 Waf 的系统。在配置过程中，它会传递必要的参数，例如安装路径 (`prefix`, `libdir`, `includedir`)，并处理交叉编译的情况。
*   **构建外部项目:**  通过创建 Meson 的 `CustomTarget` 来触发外部项目的构建过程。这个 `CustomTarget` 会执行 `make` (或其他指定的构建命令)。
*   **安装外部项目:** 虽然代码本身没有显式的安装步骤，但它通过配置过程设置了外部项目的安装路径，并且创建了一个 `InstallDir` 对象，指示 Meson 将外部项目构建的产物（通常安装到 `dist` 目录下）包含到最终的 Frida 安装包中。
*   **提供依赖:**  提供 `dependency` 方法，允许 Frida 的其他组件声明对外部项目构建的库的依赖。这个方法会返回一个 `InternalDependency` 对象，其中包含了外部库的头文件路径和链接参数。
*   **处理环境变量:**  在配置和构建外部项目时，可以设置和传递环境变量，例如 `CFLAGS`, `LDFLAGS`, `CC` 等，确保外部项目能够正确编译和链接。
*   **日志记录:**  记录外部项目的配置和构建过程，方便调试。
*   **处理依赖关系:**  可以声明外部项目依赖于其他 Meson 构建的目标 (`BuildTarget`, `CustomTarget`)，确保构建顺序正确。

**2. 与逆向方法的关系举例说明:**

Frida 本身就是一个强大的逆向工程工具。这个模块通过集成外部项目，可以扩展 Frida 的功能，例如：

*   **集成反汇编引擎:** 假设你想在 Frida 脚本中使用一个高性能的反汇编引擎，而这个引擎是用 C++ 开发的，并且使用 Autotools 进行构建。你可以使用 `external_project.add_project` 将其集成到 Frida 的构建过程中。之后，你可以通过 `dependency` 方法在 Frida 的 C 模块中链接这个反汇编引擎的库。这样，你的 Frida 脚本就能调用反汇编引擎的功能，进行更深入的程序分析。
*   **集成协议解析库:**  在逆向网络协议时，可能需要特定的协议解析库。如果这个库不是 Meson 构建的，你可以用 `external_project` 集成它。然后在 Frida 脚本中，利用这个库来解析捕获到的网络数据包。
*   **集成加解密库:**  分析加壳或加密的应用时，可能需要特定的加解密算法实现。通过集成外部的加解密库，Frida 能够动态地调用这些算法，辅助逆向分析。

**3. 涉及到二进制底层，Linux, Android 内核及框架的知识举例说明:**

*   **二进制底层:**
    *   代码中设置 `CFLAGS`, `LDFLAGS` 等环境变量，这些变量直接影响到编译器的行为，控制二进制代码的生成和链接过程。例如，通过 `CFLAGS` 可以指定优化级别、包含路径等。
    *   `dependency_method` 返回的 `link_args` (如 `-L/path/to/lib`, `-llibname`) 是链接器需要的参数，用于将编译后的目标文件链接成最终的可执行文件或库文件。
*   **Linux:**
    *   代码中假设了类似 Unix 的构建流程，例如 `configure` 脚本和 `make` 命令是很典型的 Linux/Unix 构建工具。
    *   安装路径的设置，如 `prefix`, `libdir`, `includedir`，遵循 FHS (Filesystem Hierarchy Standard)，这是 Linux 系统中常见的目录结构约定。
*   **Android 内核及框架:**
    *   尽管代码本身没有直接操作 Android 内核，但通过 Frida 对 Android 应用进行动态 instrumentation 时，可能会涉及到与 Android 框架的交互。如果需要集成一些与 Android 平台相关的原生库（例如，某些 Native Hook 框架或特定的系统调用封装库），可以使用 `external_project` 进行集成。
    *   交叉编译配置选项 (`cross_configure_options`) 的存在表明该模块考虑了交叉编译的场景，这在为 Android 或其他嵌入式平台构建软件时非常重要。`--host=@HOST@` 就是一个典型的交叉编译配置选项。

**4. 逻辑推理举例说明 (假设输入与输出):**

**假设输入 `meson.build` 文件内容:**

```meson
project('my-frida-project', 'cpp')

frida_qml_dep = dependency('frida-qml')

ext_proj = import('frida/subprojects/frida-qml/releng/meson/mesonbuild/modules/external_project.py')

ext_lib = ext_proj.add_project(
  'configure',
  configure_options: [
    '--prefix=' + get_option('prefix'),
    '--enable-shared',
    '--disable-static'
  ],
  cross_configure_options: [
    '--host=@HOST@'
  ],
  depends: [frida_qml_dep]
)

my_lib = shared_library('my_frida_module', 'my_module.c', dependencies: [ext_proj.dependency('ext_lib')])
```

**假设外部项目 `configure` 脚本会生成 `Makefile`，并且构建出一个名为 `libext_lib.so` 的共享库，头文件安装到 `${prefix}/include/ext_lib` 目录下。**

**逻辑推理与输出:**

*   `ext_proj.add_project('configure', ...)` 会执行外部项目源代码目录下的 `configure` 脚本。
*   配置脚本执行时，`configure_options` 中的 `--prefix` 会被替换为 Meson 配置的 `prefix` 选项的值。
*   `cross_configure_options` 中的 `--host=@HOST@` 会被替换为当前构建的 host 平台的 triplet。
*   Meson 会创建一个 `CustomTarget`，当需要构建 `my_lib` 时，这个 `CustomTarget` 会先被执行，运行 `make` 命令来构建外部项目。
*   `ext_proj.dependency('ext_lib')` 会返回一个 `InternalDependency` 对象，其中包含：
    *   `compile_args`: `['-I/path/to/prefix/include/ext_lib']` (假设 prefix 是 `/path/to/prefix`)
    *   `link_args`: `['-L/path/to/prefix/lib', '-lext_lib']`
*   `shared_library('my_frida_module', ...)` 在编译 `my_module.c` 时会使用 `compile_args` 中的包含路径，并在链接时使用 `link_args` 中的库路径和库名。

**5. 涉及用户或者编程常见的使用错误举例说明:**

*   **错误的配置命令:** 用户可能指定了不存在的配置脚本名称，或者配置脚本不在外部项目的源代码根目录下。例如，将 `'config'` 写成 `'configuree'`。
*   **配置选项错误:**  传递了外部项目不支持的配置选项，或者选项的格式不正确。例如，外部项目只需要 `--enable-feature`，用户却传递了 `--enable-feature=true`。
*   **依赖项缺失:**  外部项目依赖于其他库，但这些库没有被正确安装或配置，导致配置或构建失败。例如，外部项目依赖 `zlib`，但系统中没有安装 `zlib-dev` 包。
*   **环境变量设置不正确:**  外部项目的构建过程可能依赖特定的环境变量，但用户没有正确设置，导致构建失败。
*   **路径错误:**  如果外部项目的配置或构建脚本中硬编码了路径，而这些路径在 Frida 的构建环境中不存在，会导致错误。
*   **交叉编译配置错误:**  在交叉编译时，`cross_configure_options` 没有正确设置，导致为目标平台构建失败。例如，忘记设置 `--host` 选项。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户想要在 Frida 中使用一个外部的 C/C++ 库。**
2. **用户编辑 Frida 项目的 `meson.build` 文件。**
3. **用户导入了 `external_project.py` 模块:**  `ext_proj = import('frida/subprojects/frida-qml/releng/meson/mesonbuild/modules/external_project.py')`
4. **用户调用 `ext_proj.add_project()` 方法，并传入必要的参数，例如配置命令、配置选项等。** 这就在 Meson 的构建图中定义了一个外部项目。
5. **用户尝试构建 Frida 项目 (例如运行 `meson compile`)。**
6. **Meson 在构建过程中，会执行 `external_project.py` 模块中的代码。**
7. **首先，`ExternalProject` 类的 `__init__` 方法会被调用**，初始化外部项目的相关信息。
8. **然后，`_configure` 方法会被调用**，执行外部项目的配置命令。如果配置失败，会在 `_run` 方法中抛出异常，并记录日志。
9. **接着，`_create_targets` 方法会被调用**，创建一个 `CustomTarget` 来表示外部项目的构建过程。
10. **当 Meson 调度到这个 `CustomTarget` 时，会执行 `make` 命令**（或者其他配置的构建命令）。如果构建失败，同样会在 `_run` 方法中抛出异常并记录日志。
11. **如果 Frida 的其他组件需要依赖这个外部项目，会调用 `dependency_method`** 获取依赖信息。

**调试线索:**

*   **查看 Meson 的输出信息:** Meson 在执行配置和构建外部项目时会输出相应的日志信息，可以查看是否有错误或警告。
*   **查看外部项目的日志文件:**  代码中 `_run` 方法会记录配置和构建的日志到 `${self.name}-{step}.log` 文件中。这些日志包含了更详细的外部项目构建过程的输出，是排查问题的关键。
*   **检查 `meson.build` 文件:**  确认 `add_project` 方法的参数是否正确，例如配置命令、选项、依赖项等。
*   **手动执行配置和构建命令:**  可以尝试在外部项目的源代码目录下手动执行配置命令和构建命令，以排除 Frida 构建系统本身的问题。 这样可以更直接地观察外部项目构建过程中的错误。
*   **检查环境变量:** 确认在 Frida 的构建环境中，外部项目所需的任何环境变量都已正确设置。

总而言之，`external_project.py` 模块是 Frida 构建系统中一个关键的组成部分，它桥接了 Meson 构建系统和各种外部构建系统，使得 Frida 能够方便地集成和利用来自不同来源的组件，极大地扩展了 Frida 的能力。这对于像 Frida 这样复杂的工具来说至关重要，因为它允许开发者利用现有的、成熟的第三方库，而无需将其完全移植到 Meson 构建系统。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/modules/external_project.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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