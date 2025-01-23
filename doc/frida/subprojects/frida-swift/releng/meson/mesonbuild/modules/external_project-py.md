Response:
Let's break down the thought process for analyzing this Python code and answering the user's questions.

**1. Understanding the Goal:**

The core request is to understand what this Python file does within the context of Frida, specifically focusing on its interactions with reverse engineering, low-level concepts, logic, potential errors, and how a user might trigger its execution.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for relevant keywords and patterns. This helps in forming an initial understanding of the code's purpose. Some key observations:

* **`ExternalProject` class:** This strongly suggests managing external build processes.
* **`configure_command`:**  Indicates running a configuration script.
* **`make`:** Points to using `make` (or potentially `waf`) for building.
* **`dependency_method`:**  Likely defines how this external project provides dependencies to the main Frida build.
* **`prefix`, `libdir`, `includedir`:**  Standard installation directory variables.
* **`CFLAGS`, `LDFLAGS`:**  Compiler and linker flags.
* **`Popen_safe`:** Running external commands.
* **`frida/subprojects/frida-swift`:** The file path itself is crucial context, indicating this is about incorporating Swift code into Frida.
* **`releng/meson/mesonbuild`:**  Confirms this is part of the release engineering process and uses the Meson build system.

**3. Deconstructing the `ExternalProject` Class:**

This is the heart of the file. The constructor (`__init__`) and its methods need detailed examination:

* **Constructor (`__init__`)**:  Focus on the arguments and how they initialize the object's state. Note the handling of source, build, and install directories. The `_configure` call is significant, triggering the configuration process.
* **`_configure`**: This is where the external project's configuration is handled. Observe the logic for handling different `configure_command` values (`waf` vs. a generic script). Pay attention to how environment variables (like `CFLAGS`, `LDFLAGS`) are set up.
* **`_create_targets`**:  This method defines how Meson integrates the external project into its build system. The use of `CustomTarget` is key. Recognize that the output of the external build will be a "stamp" file.
* **`dependency_method`**: How does this external project expose its libraries and headers to other parts of Frida?  Notice the creation of an `InternalDependency` object.

**4. Analyzing the `ExternalProjectModule` Class:**

This class registers the `add_project` method, which is the entry point for using this functionality within Meson. Look at the arguments and how they map to the `ExternalProject` constructor.

**5. Connecting to Reverse Engineering:**

The file path and the context of Frida being a dynamic instrumentation tool are the primary connections here. Swift is a compiled language, so incorporating Swift code likely means building a library. This library could be used to:

* **Inject into processes:** Frida's core functionality.
* **Hook functions:**  Intercepting and modifying function calls in a target process.
* **Interact with the target's memory:** Reading and writing data.

The `dependency_method` is how this external Swift code is made available to Frida's core, which is used for reverse engineering tasks.

**6. Identifying Low-Level Concepts:**

* **Binary compilation:** The entire process of configuring and building Swift code results in binary artifacts (libraries).
* **Linking:**  The `dependency_method` generates linker flags (`-L`, `-l`) to link against the built Swift library.
* **Operating system paths:** The code manipulates file paths extensively, which are fundamental to OS interaction.
* **Environment variables:**  `CFLAGS`, `LDFLAGS`, and others directly influence the compilation and linking processes.
* **Process execution:** `Popen_safe` interacts directly with the operating system to run external commands.

**7. Tracing User Interaction and Debugging:**

Imagine a developer wants to use Swift to write Frida gadgets. They would:

1. **Create a Swift project.**
2. **Use Meson to build Frida.**
3. **Within the Frida Meson build files, use the `external_project.add_project` function.** This is the crucial step where this Python code comes into play.
4. **Specify the configuration command and options for their Swift project.**
5. **Use `external_project.dependency` to link against the built Swift library.**

If something goes wrong, debugging would involve:

* **Checking the generated log files:** The code explicitly creates log files for the configure and build steps.
* **Verifying the configuration options:** Incorrect paths or flags can cause issues.
* **Inspecting the generated Meson build files:** To see how the external project is integrated.

**8. Identifying Potential Errors:**

Focus on areas where user input is involved or external processes are run:

* **Incorrect configure options:**  Leading to build failures.
* **Missing dependencies for the Swift project:** The external build might fail.
* **Incorrect paths:**  If the source directory or install locations are wrong.
* **Environment issues:** If required tools (like `make`, `swiftc`) are not in the `PATH`.

**9. Logic and Assumptions:**

* **Assumption:** The `configure_command` is either `waf` or a script in the source directory.
* **Logic:**  The code parses configuration options and substitutes variables. It handles cross-compilation scenarios. The `dependency_method` builds a standard dependency object.

**10. Structuring the Answer:**

Organize the information logically according to the user's questions:

* **Functionality:**  Provide a high-level overview and then detail the key methods.
* **Reverse Engineering:** Explicitly connect the code to Frida's purpose and how the external project enables Swift-based gadgets.
* **Low-Level Concepts:**  List the relevant concepts and provide brief explanations.
* **Logic and Assumptions:** Present a simple example to illustrate the input/output.
* **User Errors:**  Give concrete examples of common mistakes.
* **User Operation and Debugging:**  Describe the steps a user would take and where they might encounter issues.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** This might be just about building any external project.
* **Correction:** The file path (`frida-swift`) strongly suggests it's specifically for integrating Swift.
* **Initial thought:**  The environment variable handling might be too generic.
* **Correction:**  The code explicitly sets `CFLAGS` and `LDFLAGS`, which are critical for compilation and linking, making it relevant to low-level details.
* **Initial thought:**  Focusing too much on individual lines of code.
* **Correction:**  Shifting to understanding the overall flow and the purpose of each class and method is more important.

By following these steps, a comprehensive and accurate analysis of the Python code can be achieved, addressing all aspects of the user's request.
好的，让我们来详细分析一下 `frida/subprojects/frida-swift/releng/meson/mesonbuild/modules/external_project.py` 这个文件。

**文件功能总览**

这个 Python 文件是 Frida 项目中用于集成外部构建项目的 Meson 模块。它的主要功能是允许 Frida 的构建系统（Meson）去管理和构建不是使用 Meson 构建的外部项目（例如，使用 autotools 的项目，或者像这里看到的，可能是 Swift 项目）。

**具体功能分解：**

1. **定义 `ExternalProject` 类:**
   - 负责代表一个需要集成的外部项目。
   - 存储外部项目的配置信息，例如配置命令 (`configure_command`)、配置选项 (`configure_options`、`cross_configure_options`)、环境变量 (`env`)、是否显示详细输出 (`verbose`) 等。
   - 管理外部项目的源代码目录 (`src_dir`)、构建目录 (`build_dir`) 和安装目录 (`install_dir`)。
   - 包含 `_configure` 方法，用于执行外部项目的配置脚本（例如 `configure` 或 `waf configure`）。
   - 包含 `_create_targets` 方法，用于在 Meson 中创建自定义构建目标 (`CustomTarget`)，该目标会触发外部项目的构建过程。
   - 包含 `dependency_method` 方法，用于将外部项目构建的库文件和头文件以 Meson 依赖的形式提供给 Frida 的其他部分。

2. **定义 `ExternalProjectModule` 类:**
   - 继承自 `ExtensionModule`，表示这是一个 Meson 的扩展模块。
   - 注册 `add_project` 方法，该方法是用户在 `meson.build` 文件中调用以添加外部项目的入口点。
   - `add_project` 方法会创建 `ExternalProject` 的实例。

**与逆向方法的关联及举例说明**

这个模块的核心作用是**将 Swift 代码集成到 Frida 中**。由于 Frida 是一个动态插桩工具，常用于逆向工程，因此这个模块直接关系到如何使用 Swift 编写 Frida 的组件，例如：

* **编写 Frida Gadget 或 Agent 的一部分:**  你可以使用 Swift 来编写需要在目标进程中运行的代码片段，这些代码可以用于 hook 函数、修改内存、监控行为等逆向分析任务。
* **实现与 Frida 核心的 Swift 绑定:**  可能用于构建 Frida 的 Swift API，方便开发者使用 Swift 来控制 Frida。

**举例说明:**

假设你有一个用 Swift 编写的库 `MySwiftLib.swift`，它包含了一些你希望在 Frida 中使用的逆向分析功能，例如一个用于解析特定数据结构的函数。你可以使用 `external_project.add_project` 将这个 Swift 项目集成到 Frida 的构建过程中。

在 `meson.build` 文件中，你可能会这样写：

```meson
swift_proj = import('external_project')
my_swift_lib = swift_proj.add_project(
  'swift build -c release', # 配置命令，这里使用 swift 包管理器的构建命令
  configure_options: [],
  cross_configure_options: [],
  verbose: true,
  # 假设 Swift 项目在 frida/subprojects/frida-swift/my_swift_lib 目录下
  env: {},
  depends: []
)

# 获取 Swift 库的依赖
my_swift_dep = my_swift_lib.dependency('MySwiftLib')

# 将 Swift 库链接到 Frida 的某个组件
frida_component = shared_library('frida_component',
  'frida_component.c',
  dependencies: my_swift_dep,
  # ... 其他设置
)
```

在这个例子中，`external_project.add_project` 负责构建你的 Swift 库，而 `my_swift_lib.dependency('MySwiftLib')` 则会生成一个 Meson 依赖对象，包含了链接 Swift 库所需的库文件路径和头文件路径，以便 `frida_component` 可以使用 Swift 代码。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明**

虽然这个 Python 文件本身主要是构建系统的配置，但它所管理的外部项目（Swift 代码）最终会编译成二进制代码，并与 Frida 的其他部分（可能是 C/C++ 代码）链接在一起。因此，它间接地涉及到以下知识：

* **二进制文件:**  Swift 代码会被编译成机器码，生成动态链接库 (`.so` 或 `.dylib`)。
* **链接器:**  Meson 和底层的链接器（如 `ld`）会处理将 Swift 库链接到 Frida 组件的过程。
* **操作系统接口:**  Frida 需要与目标进程进行交互，这涉及到操作系统提供的各种 API，例如用于内存操作、进程控制、信号处理等。Swift 代码如果用于编写 Frida Gadget，也需要利用这些接口。
* **平台差异:**  `cross_configure_options` 的存在表明需要考虑交叉编译的情况，例如在 Linux 主机上为 Android 设备构建 Frida 组件。这涉及到不同平台上的 ABI (Application Binary Interface)、系统调用约定、库文件路径等差异。
* **Android 框架:** 如果 Swift 代码用于在 Android 上进行逆向，可能需要与 Android 的运行时环境 (ART) 或 Native 代码进行交互。

**举例说明:**

在 `_configure` 方法中，代码会设置环境变量，例如 `CFLAGS` 和 `LDFLAGS`。这些环境变量直接影响 Swift 代码的编译和链接过程：

```python
        for lang, compiler in self.env.coredata.compilers[MachineChoice.HOST].items():
            if any(lang not in i for i in (ENV_VAR_PROG_MAP, CFLAGS_MAPPING)):
                continue
            cargs = self.env.coredata.get_external_args(MachineChoice.HOST, lang)
            assert isinstance(cargs, list), 'for mypy'
            self.run_env[ENV_VAR_PROG_MAP[lang]] = self._quote_and_join(compiler.get_exelist())
            self.run_env[CFLAGS_MAPPING[lang]] = self._quote_and_join(cargs)
```

这里的 `CFLAGS_MAPPING` 就包含了 C 编译器相关的环境变量名（例如 `CFLAGS`、`CXXFLAGS`），这些变量会传递给 Swift 的底层编译工具链，影响生成的二进制代码。例如，你可以通过 `CFLAGS` 添加特定的优化选项或者定义宏。

**逻辑推理及假设输入与输出**

**假设输入:**

在 `meson.build` 文件中，用户调用 `external_project.add_project`，并提供以下参数：

```meson
my_swift_proj = external_project_mod.add_project(
  'swift build -c release',
  configure_options: ['-Xswiftc', '-DDEBUG'],
  env: {'MY_CUSTOM_VAR': 'my_value'}
)
```

**逻辑推理:**

1. `ExternalProjectModule.add_project` 方法被调用。
2. 创建 `ExternalProject` 的实例，并将传入的参数存储起来。
3. 在 `ExternalProject._configure` 方法中：
   - 配置命令会是 `['swift', 'build', '-c', 'release']`。
   - `configure_options` 会包含 `['-Xswiftc', '-DDEBUG']`，这些选项会被传递给 Swift 的构建系统。
   - 环境变量 `MY_CUSTOM_VAR` 会被添加到 `self.run_env` 中。
   - 执行 `swift build -c release` 命令，工作目录为 Swift 项目的源代码目录。
4. 在 `ExternalProject._create_targets` 方法中，会创建一个 `CustomTarget`，当 Meson 构建到这个目标时，会再次执行 `swift build -c release` 命令来构建 Swift 项目。
5. 如果用户后续调用 `my_swift_proj.dependency('MySwiftLib')`，`dependency_method` 会根据 Swift 项目的构建结果，推断出库文件和头文件的位置，并返回一个 `InternalDependency` 对象。

**假设输出:**

- 如果 Swift 项目构建成功，`CustomTarget` 会生成一个 stamp 文件，表示构建完成。
- `dependency_method` 返回的 `InternalDependency` 对象会包含指向 Swift 库文件（例如 `libMySwiftLib.so` 或 `libMySwiftLib.dylib`）和头文件目录的路径，这些路径是根据 `install_dir`、`libdir` 和 `includedir` 等信息计算出来的。

**涉及用户或者编程常见的使用错误及举例说明**

1. **配置命令错误:** 用户提供的 `configure_command` 不正确，导致外部项目的配置或构建失败。
   - **例子:**  如果 Swift 项目需要先执行 `swift package resolve` 来解析依赖，但用户只提供了 `'swift build'` 作为配置命令，可能会导致构建失败。

2. **配置选项错误:**  提供的 `configure_options` 或 `cross_configure_options` 不被外部项目接受。
   - **例子:**  对于一个使用 autotools 的项目，如果传递了错误的 `--prefix` 路径，可能导致文件安装到错误的位置。

3. **依赖关系错误:**  在 `meson.build` 中使用 `external_project.dependency` 时，提供的库名 (`libname`) 与外部项目实际生成的库名不符。
   - **例子:**  Swift 项目生成的是 `libMySwiftModule.so`，但用户在 `dependency_method` 中使用了 `'MySwiftLib'`，导致链接器找不到库文件。

4. **环境变量设置错误:**  用户期望传递特定的环境变量给外部构建过程，但 `env` 参数设置不正确。
   - **例子:**  Swift 项目可能依赖于某个环境变量来指定 SDK 路径，如果用户没有正确设置 `env`，构建可能会失败。

5. **未声明依赖:**  如果外部项目的构建依赖于其他 Meson 目标，但没有通过 `depends` 参数显式声明，可能导致构建顺序错误。
   - **例子:**  如果 Swift 项目的构建依赖于先生成一些配置文件，而这些配置文件的生成由另一个 Meson 目标管理，则需要将该目标添加到 `depends` 中。

**说明用户操作是如何一步步的到达这里，作为调试线索**

当 Frida 的开发者或贡献者希望将 Swift 代码集成到 Frida 的构建系统中时，他们会修改 Frida 项目的 `meson.build` 文件。以下是可能的操作步骤：

1. **定位到需要集成 Swift 代码的模块:**  开发者会确定 Swift 代码应该集成到 Frida 的哪个组件中。

2. **修改 `meson.build` 文件:**  在相应的 `meson.build` 文件中，开发者会：
   - 导入 `external_project` 模块: `external_project_mod = import('external_project')`
   - 调用 `external_project_mod.add_project` 函数，提供 Swift 项目的配置信息，例如 Swift 构建命令、源代码路径等。
   - 调用返回的对象的 `dependency` 方法，获取 Swift 库的依赖信息。
   - 将获取到的依赖信息添加到需要链接 Swift 库的 Frida 组件的构建定义中（例如 `shared_library` 或 `executable` 函数的 `dependencies` 参数）。

3. **运行 Meson 配置:**  开发者会在 Frida 项目的构建目录下运行 `meson setup ..` 或 `meson configure` 命令，Meson 会解析 `meson.build` 文件，并执行 `external_project.py` 模块中的代码。

4. **运行 Meson 构建:**  开发者运行 `meson compile` 或 `ninja` 命令来开始构建过程。当构建到由 `external_project.add_project` 创建的 `CustomTarget` 时，Meson 会执行配置和构建外部 Swift 项目的命令。

**作为调试线索:**

如果集成 Swift 代码的过程中出现问题，开发者可以按照以下步骤进行调试：

1. **检查 `meson.build` 文件:**  确认 `external_project.add_project` 和 `dependency` 的调用参数是否正确，例如配置命令、库名、依赖关系等。

2. **查看 Meson 的日志输出:**  Meson 会在控制台输出构建过程的信息，包括执行的外部命令及其输出。

3. **查看外部项目的构建日志:**  `ExternalProject` 模块会将外部项目的配置和构建日志保存在 `${build_dir}/meson-logs/` 目录下，可以查看这些日志以获取更详细的错误信息。具体的文件名类似于 `my_swift_project-configure.log` 和 `my_swift_project-build.log`。

4. **使用 `verbose: true` 参数:**  在调用 `add_project` 时设置 `verbose: true` 可以让 Meson 输出更详细的外部命令执行信息，方便追踪问题。

5. **逐步执行 `external_project.py` 代码:**  如果需要深入了解 Meson 如何处理外部项目，可以使用 Python 调试器（例如 `pdb`）来逐步执行 `external_project.py` 中的代码，查看变量的值和执行流程。这需要对 Meson 的内部工作原理有一定的了解。

总而言之，`external_project.py` 是 Frida 构建系统中一个关键的组件，它使得将非 Meson 构建的外部项目（特别是 Swift 项目）集成到 Frida 中成为可能，从而扩展了 Frida 的功能和灵活性，尤其是在利用 Swift 语言进行逆向工程方面。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/modules/external_project.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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