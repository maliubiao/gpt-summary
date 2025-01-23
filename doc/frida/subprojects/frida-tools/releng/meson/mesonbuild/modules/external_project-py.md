Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding: The Big Picture**

The first step is to recognize the file path: `frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/external_project.py`. This immediately tells us:

* **Frida:**  This code is part of the Frida dynamic instrumentation toolkit.
* **Subprojects & releng:** It's related to how Frida manages external dependencies and the release engineering process.
* **Meson:**  The build system being used is Meson.
* **Modules:** This is a Meson module, extending Meson's functionality.
* **external_project:** The module's purpose is to integrate external projects into the Meson build.

The code itself confirms this through imports like `mesonbuild`, `mlog`, `build`, and the class names `ExternalProject` and `ExternalProjectModule`.

**2. Core Functionality Identification (Scanning the Code)**

Next, I'd scan the code for key classes, methods, and variables to understand the primary actions:

* **`ExternalProject` class:** This seems to be the core logic for handling a single external project.
    * `__init__`:  Initialization, taking arguments like `configure_command`, `configure_options`, etc. This suggests it sets up the integration.
    * `_configure`: Likely responsible for running the external project's configure script.
    * `_create_targets`: Creates Meson build targets for the external project.
    * `dependency_method`: Provides a way to create a Meson dependency object for libraries built by the external project.
* **`ExternalProjectModule` class:** This is the Meson module definition.
    * `add_project`:  The main entry point for using this module, taking the configure command and options as arguments.
* **Key methods and variables:**  `_run`, `make`, `configure_command`, `configure_options`, `cross_configure_options`, `prefix`, `libdir`, `includedir`. These give clues about the steps involved and the configuration options.

**3. Detailed Analysis of Key Methods and Concepts**

Now, let's delve deeper into the crucial parts:

* **`ExternalProject.__init__`:** Notice how it sets up paths (`src_dir`, `build_dir`, `install_dir`), handles prefixes, and calls `_configure`. This tells us about the directory structure and the initial setup.
* **`ExternalProject._configure`:**  The logic branches based on `configure_command` (e.g., 'waf' or a generic script). It constructs the configure command, handles cross-compilation, and sets environment variables. The interaction with `state.find_program` is important for locating executables.
* **`ExternalProject._create_targets`:** This is where the integration with Meson happens. It creates a `CustomTarget` that executes the external project's build system (like `make`). The `--internal externalproject` flag is a giveaway that Meson is aware of this special handling. The creation of an `InstallDir` target suggests how the external project's artifacts are installed.
* **`ExternalProject.dependency_method`:** This method is key for making the outputs of the external project usable by other parts of the Frida build. It creates an `InternalDependency` object with the necessary include directories and library linking information.
* **`ExternalProjectModule.add_project`:** This is the user-facing function in Meson. It instantiates `ExternalProject` and returns the build targets. The `@typed_kwargs` decorator indicates the expected arguments and their types.

**4. Connecting to the Prompts**

With a good understanding of the code, I can now address the specific questions in the prompt:

* **Functionality:**  Summarize the purpose and key actions of the module.
* **Reverse Engineering Relation:**  Think about how external libraries are often used in reverse engineering (e.g., disassemblers, decompilers). The ability to integrate these tools into a build process is relevant.
* **Binary/Kernel/Android Knowledge:**  Look for areas where the code interacts with lower-level concepts:
    * Setting environment variables like `CFLAGS`, `LDFLAGS`, `CC`.
    * Handling cross-compilation (`--host`).
    * The concept of prefix, libdir, and includedir, which are standard in Unix-like systems.
* **Logical Inference:** Analyze conditional logic (like the `if self.configure_command == 'waf'`) and how inputs influence outputs.
* **User Errors:** Identify common mistakes users might make when calling `add_project` or configuring the external project (e.g., incorrect paths, missing dependencies).
* **User Operations & Debugging:**  Trace back how a user might end up interacting with this code (defining an external project in their `meson.build` file) and how this code aids in debugging (logging, error handling).

**5. Structuring the Answer**

Finally, organize the findings into a clear and structured answer, using headings and bullet points for readability. Provide specific code snippets and examples to illustrate the points.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** Maybe the module directly builds the external project.
* **Correction:** The code uses `CustomTarget` and executes the external project's build system (`make` or `waf`). This is a more accurate understanding of its role as an *integrator*.
* **Initial thought:**  Focus only on the `ExternalProject` class.
* **Correction:**  Recognize the importance of `ExternalProjectModule` as the entry point and the interaction between the two classes.

By following this systematic approach, starting with the big picture and drilling down into details, I can effectively analyze and explain the functionality of this complex Python code.
这个Python文件 `external_project.py` 是 Frida 工具链中 Meson 构建系统的一个模块，其主要功能是**允许在当前的 Frida 构建过程中集成和构建外部项目**。这意味着你可以在 Frida 的构建流程中，自动地下载、配置、编译和安装其他独立的软件项目。

下面详细列举其功能，并结合逆向、底层知识、逻辑推理、用户错误和调试线索进行说明：

**1. 功能列表:**

* **声明和配置外部项目:**  `add_project` 方法允许用户在 Meson 构建文件中声明一个需要集成的外部项目。这包括指定外部项目的配置命令（例如 `configure` 脚本），配置选项，交叉编译选项，以及依赖项。
* **执行外部项目的配置:** `_configure` 方法负责执行外部项目的配置脚本。它会根据用户提供的选项和当前 Frida 的构建环境（包括交叉编译设置），构造并运行配置命令。
* **创建 Meson 构建目标:** `_create_targets` 方法创建一个 Meson `CustomTarget`，代表外部项目的构建过程。这个目标会执行外部项目的构建命令（通常是 `make`）。同时也会创建 `InstallDir` 目标来处理外部项目的安装。
* **创建外部项目的依赖:** `dependency_method` 允许将外部项目构建的库声明为 Frida 的依赖项。这使得 Frida 的其他部分可以链接到外部项目生成的库。
* **处理环境变量:**  该模块会设置一些常见的环境变量，例如 `CFLAGS`, `CC`, `LDFLAGS`，以便外部项目的构建系统能够正确地使用 Frida 的编译器和链接器设置。
* **处理日志:**  模块会将外部项目的配置和构建过程中的输出记录到日志文件中，方便用户查看和调试。
* **处理 `waf` 构建系统:**  模块对使用 `waf` 作为构建系统的外部项目提供了特殊的支持。
* **支持依赖关系:** `depends` 关键字允许声明当前外部项目依赖于其他的 Frida 构建目标。

**2. 与逆向方法的关联及举例说明:**

这个模块与逆向工程的方法有直接关系，因为它允许 Frida 集成各种用于逆向分析的工具或库。

**例子:**

假设你想在 Frida 中使用一个名为 "Capstone" 的反汇编库。Capstone 是一个独立的开源项目。你可以使用 `external_project.add_project` 将 Capstone 集成到 Frida 的构建过程中：

```python
capstone_proj = external_project.add_project(
  'cmake',  # Capstone 使用 CMake 作为构建系统
  configure_options=['-DCMAKE_INSTALL_PREFIX=' + meson.build_root() + '/capstone_install'],
  # ... 其他选项
)

capstone_dep = capstone_proj.get_variable('dependency')('capstone') # 假设 Capstone 安装了一个名为 libcapstone 的库

# 然后可以在 Frida 的其他目标中使用 capstone_dep 作为依赖
frida_target = library('my_frida_module', 'my_frida_module.c', dependencies: [capstone_dep])
```

在这个例子中：

* `external_project.add_project('cmake', ...)`  指示 Meson 执行 Capstone 的 CMake 配置。
* `configure_options` 指定了 Capstone 的安装路径。
* `capstone_proj.get_variable('dependency')('capstone')` 创建了一个 Meson 依赖对象，表示 Capstone 构建的 `libcapstone` 库。
* `library('my_frida_module', ... dependencies: [capstone_dep])` 表明你的 Frida 模块依赖于 Capstone 库，Meson 会确保 Capstone 先被构建和链接。

**3. 涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

该模块在处理外部项目构建时，会涉及到一些底层知识：

* **二进制可执行文件:**  `state.find_program()` 用于查找外部项目的配置脚本或构建工具（例如 `configure`, `make`, `waf`），这些都是二进制可执行文件。
* **编译器和链接器:**  模块会设置 `CFLAGS`, `CC`, `LDFLAGS` 等环境变量，这些变量直接影响外部项目如何使用编译器（例如 GCC, Clang）和链接器来生成二进制代码。
* **库文件链接:**  `dependency_method` 生成的依赖信息包含了库文件的路径（`-L`）和库名称（`-l`），这是链接器需要的参数。
* **交叉编译:**  模块考虑了交叉编译的情况，允许用户提供 `cross_configure_options`，以便为目标平台（例如 Android）配置外部项目。
* **文件路径和安装:**  模块处理文件路径（`prefix`, `libdir`, `includedir`）和安装过程，这涉及到文件系统的操作。

**例子:**

在为 Android 平台构建 Frida 时，你可能需要集成一个仅在 Android 上可用的库。`cross_configure_options` 可以用来指定 Android 特定的配置选项：

```python
android_lib = external_project.add_project(
  'configure',
  configure_options=['--prefix=' + meson.build_root() + '/android_install'],
  cross_configure_options=['--host=arm-linux-androideabi'], # 指定目标架构
  # ... 其他选项
)
```

这里 `--host=arm-linux-androideabi`  是传递给外部项目 `configure` 脚本的交叉编译选项，指示它为 ARM 架构的 Android 系统进行配置。

**4. 逻辑推理及假设输入与输出:**

模块内部存在一些逻辑推理，例如根据 `configure_command` 的值来判断外部项目使用的构建系统，并执行不同的配置流程。

**假设输入:**

* `configure_command`: "configure"
* `configure_options`: ["--enable-feature1", "--disable-feature2"]
* Frida 的构建目录：`/path/to/frida/build`
* 外部项目源代码目录：`/path/to/external/project`

**逻辑推理:**

1. 由于 `configure_command` 是 "configure"，模块会假设外部项目使用传统的 `configure` 脚本进行配置。
2. 模块会查找 `/path/to/external/project/configure` 这个可执行文件。
3. 模块会构建配置命令，可能类似于：`[/path/to/external/project/configure, --prefix=/path/to/frida/build/external_project_name/dist, --enable-feature1, --disable-feature2]` （实际命令还会包含其他默认选项和环境变量）。
4. 模块会在外部项目的构建目录中执行该配置命令。

**预期输出:**

* 如果配置成功，会在外部项目的构建目录中生成 Makefile 或其他构建系统所需的文件。
* 日志文件中会记录配置命令的执行过程和输出。

**5. 涉及用户或者编程常见的使用错误及举例说明:**

用户在使用 `external_project` 模块时，可能会犯以下错误：

* **配置命令错误:**  `configure_command` 指定的路径不正确，或者外部项目根本没有配置脚本。
    * **例子:**  拼写错误，将 `configure` 写成 `configre`。
* **配置选项错误:**  提供的 `configure_options` 不被外部项目的配置脚本所接受。
    * **例子:**  为使用 CMake 的项目传递了 Autotools 的选项。
* **依赖项缺失:**  外部项目依赖于其他库或工具，但这些依赖项没有被正确安装或声明。
    * **例子:**  外部项目需要 `pkg-config` 才能找到某个库，但用户的系统上没有安装 `pkg-config` 或者环境变量没有正确设置。
* **路径错误:**  在 `dependency_method` 中指定的库名称或子目录不正确。
    * **例子:**  外部项目将库安装在 `lib64` 目录下，但 `dependency_method` 中没有指定正确的 `subdir`。
* **权限问题:**  Frida 构建过程没有足够的权限在外部项目的源代码目录或构建目录中进行操作。

**6. 用户操作是如何一步步的到达这里，作为调试线索:**

要到达 `frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/external_project.py` 的代码，用户的操作流程通常是：

1. **用户编写 Frida 的 `meson.build` 文件:** 用户想要在 Frida 的构建过程中集成一个外部项目，因此会在 Frida 的 `meson.build` 文件中使用 `external_project.add_project()` 函数。
2. **用户运行 Meson 配置:** 用户在 Frida 的源代码根目录下运行 `meson setup build` 命令（或者类似的命令）来配置构建环境。
3. **Meson 解析 `meson.build`:** Meson 会读取并解析 `meson.build` 文件，当遇到 `external_project.add_project()` 调用时，会加载 `external_project.py` 模块。
4. **执行 `add_project` 方法:** Meson 会调用 `external_project.py` 中的 `add_project` 方法，并传入用户在 `meson.build` 中提供的参数。
5. **创建 `ExternalProject` 实例:** `add_project` 方法会创建一个 `ExternalProject` 类的实例，该类的 `__init__` 方法会被调用。
6. **执行配置和构建:**  在构建阶段，Meson 会执行 `ExternalProject` 实例中的 `_configure` 和 `_create_targets` 方法，从而调用外部项目的配置和构建命令。

**作为调试线索:**

* **检查 `meson.build` 文件:**  确认 `external_project.add_project()` 的调用参数是否正确，包括配置命令、选项、依赖项等。
* **查看 Meson 的构建日志:**  Meson 的构建日志（通常在 `build/meson-log.txt` 中）会记录 `external_project` 模块的执行过程，包括调用的命令、输出和错误信息。
* **检查外部项目的日志文件:** `_run` 方法会创建外部项目的日志文件（例如 `<project_name>-configure.log`），这些文件包含了外部项目配置和构建的详细输出，可以帮助定位问题。
* **使用 Meson 的调试选项:**  Meson 提供了一些调试选项（例如 `-v` 或 `--verbose`）可以提供更详细的构建信息。
* **手动执行外部项目的命令:**  为了排除 Frida 构建系统的干扰，可以尝试手动在命令行中执行外部项目的配置和构建命令，观察是否能成功。

总而言之，`external_project.py` 是 Frida 构建系统中一个非常重要的模块，它赋予了 Frida 集成和管理外部依赖的能力，这对于构建复杂的逆向工程工具链至关重要。理解其功能和工作原理有助于用户更有效地使用 Frida，并在遇到问题时进行调试。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/external_project.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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