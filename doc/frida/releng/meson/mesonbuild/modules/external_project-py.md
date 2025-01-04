Response:
Let's break down the thought process for analyzing the provided Python code for the Frida instrumentation tool.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the `external_project.py` file. This means not just listing functions, but understanding their purpose, relating them to reverse engineering concepts (since Frida is mentioned), identifying low-level interactions, and considering user errors.

**2. Initial Code Scan - Identifying Key Classes and Functions:**

My first step is to quickly scan the code to identify the major components:

* **Classes:** `ExternalProject`, `ExternalProjectModule`. This immediately suggests a modular design. `ExternalProject` seems to be the core logic for handling external projects, while `ExternalProjectModule` likely integrates this into the Meson build system.
* **Key Methods within `ExternalProject`:** `__init__`, `_configure`, `_create_targets`, `dependency_method`, `_run`. These seem to represent the lifecycle of managing an external project.
* **Key Methods within `ExternalProjectModule`:** `__init__`, `add_project`. `add_project` likely triggers the creation of an `ExternalProject` instance.

**3. Deeper Dive into `ExternalProject` - Understanding the Workflow:**

I then focus on the `ExternalProject` class, trying to trace the execution flow:

* **`__init__`:** This is the constructor. It takes various configuration options, sets up directories, and crucially calls `_configure` and `_create_targets`. This suggests an initialization sequence. The presence of `state: 'ModuleState'` hints at integration with the Meson build system.
* **`_configure`:**  This method deals with configuring the external project. It handles different configuration systems (like `waf` or a generic script). The use of `configure_options` and `cross_configure_options` is significant. It also sets up environment variables (CFLAGS, LDFLAGS, etc.), which points to interactions with the underlying build process.
* **`_create_targets`:** This method seems to generate Meson build targets. The use of `build.CustomTarget` and `build.InstallDir` is a clear indication of this. The command constructed (`meson --internal externalproject ...`) is crucial for understanding how Meson interacts with the external build.
* **`dependency_method`:**  This method is about creating dependencies on the external project, allowing other parts of the build to depend on its outputs. The concept of `InternalDependency` with `compile_args` and `link_args` is important.
* **`_run`:** This is a utility function for executing commands. It handles logging and error checking.

**4. Relating to Reverse Engineering:**

Now I connect the dots to reverse engineering, keeping Frida's context in mind:

* **External Libraries/Tools:**  Reverse engineering often involves using external libraries or tools. This module provides a way to integrate such projects into the Frida build process. The `dependency_method` is key for linking against libraries built by the external project.
* **Build Processes:** Reverse engineering tools often require compilation. This module manages the build process of these external components.
* **Target Environment:**  The `cross_configure_options` and environment variable setup are relevant when the target being reverse engineered is different from the build machine (e.g., Android).

**5. Identifying Low-Level Interactions:**

Next, I look for interactions with the operating system and lower levels:

* **Process Execution:** The `subprocess` module is used in `_run`, indicating direct interaction with the operating system to execute commands.
* **File System Operations:** The code heavily uses `pathlib` for managing directories and files, showing interaction with the file system.
* **Environment Variables:** The manipulation of environment variables (`CFLAGS`, `LDFLAGS`, etc.) is a key interaction with the underlying build environment.
* **Conditional Logic for Platforms (Windows):**  The special handling of `prefix` on Windows shows awareness of platform-specific nuances.

**6. Logical Reasoning and Examples:**

Here, I start to think about how the code might behave in different scenarios:

* **Assumptions:** The code assumes the external project uses a `configure` script or `waf`. This is a crucial assumption.
* **Input/Output:** I imagine a scenario where an external library needs to be built. The input would be the external project's source, and the output would be the built libraries and headers. The `dependency_method` then takes the library name as input and produces a dependency object.
* **User Errors:**  I consider common mistakes users might make, like incorrect paths, missing dependencies, or wrong configuration options.

**7. Tracing User Operations (Debugging Clues):**

Finally, I consider how a user would end up interacting with this code:

* **`meson.build`:** The user would likely use the `external_project.add_project` function in their `meson.build` file.
* **`dependency`:**  Later, they might use `project.dependency()` to link against the external project.
* **Debugging:** If something goes wrong, the log files generated by `_run` would be important debugging clues. The verbose option allows for more immediate output.

**Self-Correction/Refinement:**

During this process, I might go back and refine my understanding. For example, initially, I might not fully grasp the purpose of `ModuleState`. By looking at how it's used (e.g., to get the source directory, find programs), I can infer its role in providing context within the Meson build system. Similarly, understanding the role of `InternalDependency` requires examining how it's constructed and what information it carries (compile flags, link flags, sources).

By following this structured approach, combining code analysis with knowledge of the domain (reverse engineering, build systems), and considering user interaction, I can generate a comprehensive and informative explanation of the provided code.
好的，让我们来详细分析一下 `frida/releng/meson/mesonbuild/modules/external_project.py` 这个文件的功能。

**文件功能概述**

这个 Python 文件是 Frida 项目中 Meson 构建系统的一个模块，名为 `external_project`。它的主要功能是**允许在 Frida 的构建过程中集成和构建外部的、非 Meson 管理的项目**。  这意味着 Frida 的构建系统可以调用其他构建系统（如传统的 `configure` 和 `make`，或者像 `waf` 这样的构建工具）来构建依赖的外部组件。

**与逆向方法的关系及举例说明**

这个模块与逆向工程方法密切相关，因为：

* **依赖第三方库:** 逆向工程工具通常会依赖各种第三方库来实现特定的功能，例如，处理不同的文件格式、进行加密解密、与目标进程交互等。这些库可能不是用 Meson 构建的，需要一种方式集成到 Frida 的构建流程中。
* **集成现有工具:** 有些逆向工程任务可能需要使用现有的、独立的工具。`external_project` 模块允许在 Frida 的构建过程中编译和安装这些工具，方便后续使用。
* **构建目标平台的组件:** Frida 需要在不同的目标平台（如 Android、iOS、Linux、Windows）上运行。某些平台特定的组件可能需要使用平台原生的构建工具进行构建。

**举例说明:**

假设 Frida 需要集成一个名为 "libdwarf" 的外部库来解析 DWARF 调试信息。这个库使用传统的 `configure` 和 `make` 构建系统。在 Frida 的 `meson.build` 文件中，可能会使用 `external_project.add_project` 如下：

```python
dwarf_proj = external_project.add_project(
  './libdwarf-20231026/configure',  # configure 脚本的路径
  configure_options=['--prefix=' + meson.build_root() + '/external_install/dwarf'],
  cross_configure_options=['--host=' + host_machine],
  depends=[]
)

dwarf_dep = dwarf_proj.dependency('dwarf') # 获取 libdwarf 的依赖
```

这里：

1. `external_project.add_project` 指定了外部项目的 `configure` 脚本。
2. `configure_options` 传递了配置选项，例如指定安装路径。
3. `cross_configure_options` 用于交叉编译时的配置。
4. `depends` 可以指定当前外部项目依赖的其他 Frida 构建目标。
5. `dwarf_proj.dependency('dwarf')` 声明了对外部项目构建出的名为 `dwarf` 的库的依赖，Meson 会生成相应的编译和链接参数。

**涉及到二进制底层，Linux, Android 内核及框架的知识及举例说明**

这个模块在处理外部项目时，涉及到以下底层知识：

* **二进制文件构建:**  核心是执行外部项目的构建命令（例如 `configure` 和 `make`），最终产生二进制的可执行文件或库文件。
* **链接和库依赖:** `dependency_method` 的核心功能是生成正确的链接参数 (`-L` 和 `-l`)，以便将外部库链接到 Frida 的组件中。这涉及到操作系统加载和解析二进制文件的机制。
* **Linux 系统编程:**  `configure` 脚本和 `make` 文件通常是 Linux 环境下的标准构建流程。模块需要理解这些工具的工作方式。
* **交叉编译:** `cross_configure_options` 用于处理交叉编译场景，例如在 x86 机器上构建运行在 ARM Android 设备上的组件。这需要理解不同架构的 ABI (Application Binary Interface) 和工具链。
* **Android NDK:** 如果外部项目需要在 Android 上构建，可能需要与 Android NDK (Native Development Kit) 提供的工具链和库进行交互。`cross_configure_options` 中会指定目标架构和工具链路径。
* **环境变量:**  模块会设置一些环境变量（如 `CFLAGS`, `LDFLAGS`, `CC` 等），这些环境变量会影响外部项目的构建过程，需要对构建工具链和编译原理有了解。

**举例说明:**

在 Android 交叉编译场景下，`cross_configure_options` 可能会包含 `--host=arm-linux-androideabi` 这样的参数，告知外部项目的构建系统目标平台是 Android ARM。 同时，模块内部会设置 `CC` 和 `CXX` 环境变量指向 Android NDK 提供的交叉编译器。

**逻辑推理，假设输入与输出**

**假设输入:**

* **`configure_command`:** 字符串，外部项目的配置命令，例如 `'configure'` 或 `'autogen.sh'`。
* **`configure_options`:** 字符串列表，传递给配置命令的选项，例如 `['--prefix=/usr/local', '--enable-feature']`。
* **`cross_configure_options`:** 字符串列表，交叉编译时传递给配置命令的选项，例如 `['--host=arm-linux-gnueabi']`。
* **外部项目源代码:** 存在于指定的源目录中，包含构建所需的脚本和源文件。

**逻辑推理过程:**

1. **配置阶段 (`_configure` 方法):**
   - 根据 `configure_command` 找到可执行的配置脚本。
   - 将 `configure_options` 和 `cross_configure_options` 与预定义的变量（如 `PREFIX`, `LIBDIR`）进行替换。
   - 设置必要的环境变量（如 `CFLAGS`, `LDFLAGS`）。
   - 在构建目录下执行配置命令。
2. **创建构建目标 (`_create_targets` 方法):**
   - 创建一个 Meson 自定义构建目标 (`CustomTarget`)，该目标代表了外部项目的构建过程。
   - 该自定义目标会执行 `make` 命令（或其他外部构建工具命令）。
   - 创建一个安装目录 (`InstallDir`)，用于将外部项目构建的产物安装到指定位置。
3. **创建依赖 (`dependency_method`):**
   - 当其他 Frida 组件需要依赖外部项目时，调用此方法。
   - 根据提供的库名和可选的子目录，计算出头文件和库文件的绝对路径。
   - 生成 `InternalDependency` 对象，包含编译参数（`-I` 指定头文件路径）和链接参数（`-L` 指定库文件路径，`-l` 指定库名）。

**假设输出:**

* **构建成功:** 在构建目录下生成外部项目的构建产物（库文件、可执行文件等）。在安装目录下安装这些产物。
* **`dependency_method` 返回:** 一个 `InternalDependency` 对象，包含了用于链接到外部库的编译和链接参数。

**涉及用户或者编程常见的使用错误及举例说明**

* **错误的配置命令路径:** 用户可能指定了不存在或路径错误的 `configure_command`，导致配置阶段失败。
    * **示例:** `external_project.add_project('../wrong_path/configure', ...)`
* **配置选项错误:** 传递了外部项目不支持的配置选项，导致配置失败。
    * **示例:**  某个外部项目不支持 `--enable-debug` 选项，但用户在 `configure_options` 中使用了它。
* **缺少依赖:** 外部项目依赖其他库或工具，但这些依赖没有被安装或在构建环境中不可见，导致配置或构建失败。
    * **示例:** 外部项目的 `configure` 脚本依赖 `automake` 工具，但构建环境中没有安装 `automake`。
* **交叉编译配置错误:** 在交叉编译时，`cross_configure_options` 配置不正确，例如目标架构或工具链路径设置错误。
* **依赖库名错误:** 在调用 `dependency_method` 时，提供的库名与外部项目实际生成的库名不符，导致链接失败。
    * **示例:** 外部项目生成的是 `libmylib.so.1.2.3`，但用户使用了 `dwarf_proj.dependency('mylib')`。
* **文件权限问题:** 构建过程中可能遇到文件权限不足的问题，例如无法在构建目录或安装目录创建文件。

**说明用户操作是如何一步步的到达这里，作为调试线索**

当 Frida 的开发者或用户尝试构建 Frida 并且 Frida 依赖于一个外部项目时，就会涉及到这个 `external_project.py` 模块。 典型的步骤如下：

1. **编写 `meson.build` 文件:** 用户在 Frida 项目的某个子目录下的 `meson.build` 文件中，使用 `external_project` 模块的 `add_project` 函数来声明一个外部项目。这通常发生在需要集成第三方库或工具的时候。
2. **运行 Meson 配置:** 用户在 Frida 项目的根目录下运行 `meson setup builddir` 命令来配置构建环境。Meson 会解析 `meson.build` 文件，当遇到 `external_project.add_project` 调用时，会创建 `ExternalProject` 类的实例。
3. **Meson 执行外部项目配置:** 在配置阶段，`ExternalProject` 类的 `_configure` 方法会被调用，Meson 会在指定的构建目录下执行外部项目的配置命令（例如 `configure` 脚本）。
4. **运行 Meson 构建:** 用户运行 `meson compile -C builddir` 命令开始构建。当构建到依赖外部项目的目标时，`ExternalProject` 类的 `_create_targets` 方法创建的自定义构建目标会被执行，这会触发外部项目的构建命令（例如 `make`）。
5. **获取外部项目依赖:**  Frida 的其他组件可能需要链接到外部项目构建的库。这时，会调用 `ExternalProject` 实例的 `dependency_method` 来获取外部库的依赖信息。

**调试线索:**

如果构建过程中出现与外部项目相关的问题，以下是一些调试线索：

* **查看 Meson 的输出:** Meson 的输出会显示执行的外部项目配置和构建命令，以及它们的返回状态。
* **查看外部项目的日志文件:** `_run` 方法会将外部项目的配置和构建输出记录到日志文件中，文件名通常是 `<外部项目名>-configure.log` 和 `<外部项目名>-build.log`。
* **使用 `verbose=True`:** 在 `add_project` 中设置 `verbose=True` 可以让 Meson 输出更详细的外部项目构建过程信息。
* **检查环境变量:** 确认 Meson 设置的环境变量是否符合外部项目的构建要求。
* **手动执行外部项目的构建命令:** 可以尝试在构建目录下手动执行外部项目的配置和构建命令，以隔离 Meson 的问题。
* **检查 `meson.build` 文件:** 仔细检查 `add_project` 的参数是否正确，例如路径、配置选项、依赖库名等。

希望以上分析能够帮助你理解 `frida/releng/meson/mesonbuild/modules/external_project.py` 文件的功能和它在 Frida 构建过程中的作用。

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/modules/external_project.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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