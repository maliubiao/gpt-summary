Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Goal:** The request asks for the functionality of the provided Python code, its relation to reverse engineering, low-level operations, logical reasoning, common user errors, and how a user might arrive at this code (debugging context).

2. **High-Level Overview:** The file name `external_project.py` and the class `ExternalProjectModule` strongly suggest that this code manages the building of external projects as part of a larger build system (likely Meson, given the imports and copyright). The core idea is likely to take a separate project with its own build system (like `make` or `waf`) and integrate it into the larger Frida build.

3. **Identify Key Classes and Methods:**

    * **`ExternalProject`:** This is the central class for handling a single external project. Its methods like `_configure` and `_create_targets` will be crucial.
    * **`ExternalProjectModule`:** This seems to be the Meson module that exposes the functionality to users via the `add_project` method.
    * **`dependency_method`:** This method likely provides a way for the main Frida build to depend on libraries built by the external project.

4. **Analyze `ExternalProject.__init__`:**

    * **Purpose:**  Initializes the `ExternalProject` object.
    * **Key Actions:**  Stores configuration parameters, calculates directory paths (source, build, install), and calls `_configure`.

5. **Analyze `ExternalProject._configure`:**

    * **Purpose:**  Handles the configuration step of the external project.
    * **Key Actions:** Detects the external project's build system (`waf` or something else), constructs the configure command, sets up environment variables (especially important for cross-compilation), and runs the configure command.
    * **Connections to Reverse Engineering/Low-Level:** Setting environment variables like `CFLAGS`, `CC`, `LDFLAGS` directly relates to how code is compiled and linked, fundamental to understanding binaries. Cross-compilation is a common scenario in reverse engineering, especially for embedded systems or different architectures.

6. **Analyze `ExternalProject._create_targets`:**

    * **Purpose:** Creates Meson build targets for the external project's build and installation steps.
    * **Key Actions:** Uses a `CustomTarget` to represent the external project's build process and an `InstallDir` to handle installation. The `--internal externalproject` argument in the command is a strong indicator that Meson delegates the actual execution.

7. **Analyze `ExternalProject.dependency_method`:**

    * **Purpose:**  Provides a Meson `Dependency` object representing a library built by the external project.
    * **Key Actions:** Constructs include paths and link arguments necessary for linking against the external library. This is crucial for integrating the external project's output into the main Frida build.

8. **Analyze `ExternalProjectModule.add_project`:**

    * **Purpose:**  The entry point for users to add an external project to the build.
    * **Key Actions:** Creates an `ExternalProject` instance. The `@typed_kwargs` decorator shows the available options users can configure.

9. **Relate to Reverse Engineering:**  Throughout the analysis, look for aspects directly relevant to reverse engineering:

    * **External Dependencies:**  Frida itself might depend on external libraries, and this code manages that. Reverse engineers often encounter systems with numerous dependencies.
    * **Cross-Compilation:** Building Frida for Android requires cross-compilation, which this code explicitly handles.
    * **Build Processes:** Understanding how a target is built (configure, make) is important for understanding the final binary.
    * **Library Linking:**  The `dependency_method` deals with how Frida links against external libraries, a core concept in understanding software composition.

10. **Relate to Low-Level Details:**

    * **Environment Variables:**  Directly influence the compiler and linker behavior.
    * **Compiler Flags:**  `CFLAGS`, `LDFLAGS` control optimization, debugging symbols, etc.
    * **Paths:** Managing source, build, and install directories is crucial for any build system.
    * **Process Execution:** The `_run` method uses `subprocess` to execute external commands, a fundamental OS operation.

11. **Logical Reasoning (Assumptions and Outputs):**  Consider what happens given specific inputs to the methods. For example, if `configure_command` is "configure", it assumes a standard Autotools-style configure script. If `verbose` is True, more logging is output.

12. **User Errors:** Think about common mistakes a user might make:

    * **Incorrect `configure_command`:**  Specifying the wrong script name.
    * **Missing Dependencies:** The external project might have its own dependencies.
    * **Incorrect Paths:** Problems with `prefix`, `libdir`, etc.
    * **Configuration Option Errors:** Passing invalid options to the external project's configure script.

13. **Debugging Context:** How would a developer end up looking at this file?

    * **Build Failures:** If the build of an external project fails, developers might trace the error back to this code.
    * **Adding a New External Project:** Developers modifying the Frida build system would interact with this module.
    * **Understanding Build Integration:**  Someone wanting to understand how external components are integrated into Frida.

14. **Structure the Answer:**  Organize the findings logically, starting with a general overview, then detailing specific functionalities, and finally addressing the reverse engineering, low-level, logical reasoning, user error, and debugging context aspects. Use clear headings and examples to make the explanation easy to understand.

15. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Make sure the examples are relevant and easy to grasp. For instance, initially, I might have just said "handles configuration," but then I elaborated on *how* it handles it (detecting build systems, setting env vars, etc.).
这个Python源代码文件 `external_project.py` 是 Frida 动态 Instrumentation 工具中 Meson 构建系统的一个模块，用于管理和构建外部项目作为 Frida 构建过程的一部分。 简单来说，它允许 Frida 的构建系统去调用和管理其他独立的构建系统（比如使用 `configure` 脚本和 `make`，或者使用 `waf`）。

以下是其主要功能和相关说明：

**1. 功能概述:**

* **集成外部构建系统:**  该模块的主要目的是将独立的外部项目纳入 Frida 的构建流程中。这意味着它可以下载、配置、构建和安装这些外部项目，而无需手动操作。
* **配置外部项目:** 它允许指定外部项目的配置命令（例如 `configure` 脚本的名称）以及传递给配置命令的选项。这包括标准的配置选项（`configure_options`）以及交叉编译配置选项（`cross_configure_options`）。
* **处理不同的构建系统:**  它目前支持两种主要的外部构建系统：基于 `configure` 脚本和 `make` 的系统，以及基于 `waf` 的系统。
* **设置构建环境:** 它负责设置外部项目构建所需的各种环境变量，例如编译器路径（`CC`）、编译选项（`CFLAGS`）、链接器选项（`LDFLAGS`）等。对于交叉编译，还会设置 `HOST` 变量。
* **创建 Meson 构建目标:**  该模块会创建 Meson 的 `CustomTarget`，代表外部项目的构建过程。这使得外部项目的构建可以与 Frida 的其他构建目标一同管理和调度。
* **提供依赖项:**  外部项目构建完成后，该模块可以生成一个 Meson 的 `InternalDependency` 对象，允许 Frida 的其他部分声明对外部项目构建的库文件的依赖。
* **处理安装:**  虽然代码中包含 `install_dir` 和 `InstallDir` 的相关逻辑，但主要侧重于构建，安装步骤更多是外部项目自身构建系统的责任。Meson 这里主要是创建了一个安装目录的引用。
* **日志记录:**  它会记录外部项目的配置和构建过程的日志，方便调试。

**2. 与逆向方法的关联及举例:**

该模块本身并不直接执行逆向操作，但它使得 Frida 可以依赖和集成其他可能用于逆向工程的工具或库。

* **例子:** 假设 Frida 需要依赖一个用于解析 ELF 文件格式的外部库。可以使用 `external_project.add_project` 来构建这个 ELF 解析库，然后在 Frida 的代码中使用 `external_project.dependency` 来链接这个库。这样，Frida 的开发者无需手动下载、编译和链接这个库，Meson 会自动处理。 这个 ELF 解析库在逆向分析中至关重要，因为可以帮助理解二进制文件的结构。

**3. 涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

* **二进制底层:**
    * **编译和链接选项:**  模块中设置的 `CFLAGS` 和 `LDFLAGS` 直接影响二进制文件的编译和链接方式。例如，可以设置 `-fPIC` 来生成位置无关代码，这在共享库中是必要的。
    * **库依赖:**  `dependency_method` 创建的 `InternalDependency` 对象指定了链接时需要的库文件，这直接关系到二进制文件的依赖关系。
* **Linux:**
    * **环境变量:**  构建过程依赖于 Linux 的环境变量，例如 `PATH`、`CC`、`CXX` 等。该模块会设置或调整这些环境变量来确保外部项目能够正确构建。
    * **构建工具:**  它使用了 `make` 或 `waf` 等常见的 Linux 构建工具。
    * **目录结构:**  代码中涉及到 Linux 常见的文件系统路径，如 `/usr/local`（作为 `prefix` 的默认值）。
* **Android 内核及框架:**
    * **交叉编译:**  `cross_configure_options` 用于处理交叉编译场景，这在为 Android 构建 Frida 时是必须的，因为 Frida 通常在宿主机上编译，然后在 Android 设备上运行。设置正确的 host 三元组 (architecture-vendor-os) 是关键。
    * **Android NDK:** 如果外部项目需要使用 Android 特定的 API，可能需要在配置选项中指定 Android NDK 的路径。
    * **系统库依赖:** 某些外部项目可能依赖 Android 系统库，需要在构建过程中正确链接。

**举例说明:**

假设要集成一个名为 `libdwarf` 的外部库，用于解析 DWARF 调试信息，这在逆向工程中非常有用。

```python
# 在 Frida 的 meson.build 文件中

dwarf_proj = external_project_mod.add_project(
    './build_dwarf.sh',  # 假设有一个用于构建 libdwarf 的脚本
    configure_options=['--prefix', meson.install_prefix()],
    cross_configure_options=['--host', '${host_machine}'],
    verbose=true
)

dwarf_dep = dwarf_proj.get_variable('dependency')('dwarf') # 假设 libdwarf 生成一个名为 libdwarf 的库

frida_target = library('frida', 'frida.c', dependencies: dwarf_dep)
```

在这个例子中：

* `build_dwarf.sh` 脚本可能是下载、配置和构建 `libdwarf` 的命令集合。
* `configure_options` 指定了 `libdwarf` 的安装前缀。
* `cross_configure_options` 传递了交叉编译所需的主机信息。
* `dwarf_dep` 获取了 `libdwarf` 构建完成后生成的依赖对象，可以在 `frida_target` 的链接阶段使用。

**4. 逻辑推理（假设输入与输出）:**

假设输入以下参数给 `add_project` 函数：

* `configure_command`: `'configure'`
* `configure_options`: `['--enable-shared', '--disable-static']`
* `cross_configure_options`: `['--host=arm-linux-gnueabihf']`
* `verbose`: `False`

**逻辑推理:**

1. **判断构建系统:**  由于 `configure_command` 是 `'configure'`，代码会假设这是一个基于 `configure` 和 `make` 的项目。
2. **构建配置命令:**  配置命令将被构建为类似 `['/path/to/source/dir/configure', '--prefix=/usr/local', '--libdir=/usr/local/lib', '--includedir=/usr/local/include', '--enable-shared', '--disable-static', '--host=arm-linux-gnueabihf']`。
3. **设置环境变量:**  会根据当前的构建环境和目标平台设置 `CC`、`CFLAGS`、`LDFLAGS` 等环境变量。对于交叉编译，`HOST` 环境变量也会被设置。
4. **执行配置:**  在外部项目的构建目录下执行配置命令。
5. **创建构建目标:**  创建一个 Meson `CustomTarget`，其命令会包含 `make build`。
6. **生成依赖项（如果调用 `dependency_method`）:**  如果调用了 `dependency_method` 并传入库名，例如 `'mylib'，则会生成包含 `-I/path/to/install/include` 和 `-L/path/to/install/lib -lmylib` 的 `InternalDependency` 对象。

**输出:**

* 会在构建目录下生成外部项目的构建文件（例如 Makefile）。
* 如果构建成功，会在指定的安装目录下安装外部项目的库文件和头文件。
* 调用 `dependency_method` 会返回一个 `InternalDependency` 对象，可以用于在 Frida 的其他构建目标中声明依赖。

**5. 用户或编程常见的使用错误及举例:**

* **错误的 `configure_command`:**  如果外部项目没有名为 `configure` 的脚本，或者脚本名拼写错误，会导致配置步骤失败。
    * **例子:** 用户将 `configure_command` 设置为 `'config'` 而不是 `'configure'`。
* **缺少依赖项:** 外部项目可能依赖其他库或工具，如果这些依赖项在构建环境中不存在，配置或构建会失败。
    * **例子:**  外部项目需要 `autoconf`，但构建环境中没有安装。
* **配置选项错误:**  传递给外部项目的配置选项可能不被支持或格式错误。
    * **例子:**  传递了 `--enable-feature` 但外部项目没有这个特性。
* **交叉编译配置错误:**  `cross_configure_options` 中的主机信息不正确，导致为错误的架构构建。
    * **例子:**  为 Android 构建时，`--host` 设置为 `x86_64-linux-gnu` 而不是 `arm-linux-androideabi` 或 `aarch64-linux-android`.
* **文件权限问题:**  在执行配置或构建命令时，可能由于文件权限不足导致失败。
* **环境变量冲突:**  Frida 的构建环境与外部项目的构建环境可能存在环境变量冲突。

**6. 用户操作如何一步步到达这里作为调试线索:**

当 Frida 的构建过程中涉及到外部项目时，如果构建失败，开发者可能会查看构建日志，发现与 `external_project.py` 相关的错误信息。以下是一些可能的操作步骤：

1. **修改 Frida 的 `meson.build` 文件:**  开发者想要添加或修改一个外部依赖项，因此会修改 `meson.build` 文件中调用 `external_project_mod.add_project()` 的部分。
2. **运行 Meson 配置:**  开发者运行 `meson setup build` 或类似的命令来重新配置构建系统。如果配置阶段出错，错误信息可能会指向 `external_project.py` 中处理配置的部分。
3. **运行 Meson 构建:**  开发者运行 `meson compile -C build` 或类似的命令来开始构建。如果构建外部项目的步骤失败，构建日志会显示执行的命令和错误信息，这些命令是由 `external_project.py` 生成和执行的。
4. **查看构建日志:**  构建日志通常会包含 `External project <project_name>: configure` 和 `External project <project_name>: build` 等信息，以及执行的配置和构建命令。如果命令失败，日志会包含错误输出。
5. **检查 `external_project.py` 代码:**  为了理解构建失败的原因，开发者可能会查看 `external_project.py` 的源代码，了解它是如何处理外部项目的配置和构建的，特别是 `_configure` 和 `_create_targets` 方法。
6. **调试环境变量和配置选项:**  开发者可能会尝试修改传递给 `add_project` 的 `configure_options`、`cross_configure_options` 和 `env` 参数，以解决配置或构建问题。
7. **检查外部项目的构建脚本:** 如果 `configure_command` 指向一个自定义脚本，开发者还需要检查该脚本的逻辑。

总而言之，`external_project.py` 是 Frida 构建系统中一个关键的模块，它使得 Frida 可以灵活地集成和管理外部的软件组件，这对于一个复杂的工具如 Frida 来说是非常重要的。理解这个模块的功能有助于理解 Frida 的构建过程，并在遇到与外部依赖相关的构建问题时提供调试线索。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/modules/external_project.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```