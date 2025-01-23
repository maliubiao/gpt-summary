Response:
Let's break down the thought process for analyzing this Python code snippet.

1. **Understand the Context:** The first sentence is crucial: "这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/interpreter/mesonmain.py的fridaDynamic instrumentation tool的源代码文件". This tells us:
    * **File Location:** `frida/subprojects/frida-node/releng/meson/mesonbuild/interpreter/mesonmain.py`  This gives us a strong hint about the file's purpose – it's part of the Meson build system, specifically within the context of the Frida project and its Node.js bindings. The "interpreter" part suggests this file handles some kind of script execution or interpretation.
    * **Project:** Frida Dynamic Instrumentation Tool. This is the overarching context. Knowing Frida's purpose (dynamic code instrumentation) will be important later when connecting this file to reverse engineering.
    * **Key Tool:** Meson. This is the build system. This file is part of *Meson*, not a direct part of Frida's core instrumentation engine. Its role is in *building* Frida.

2. **Initial Code Scan - Identify Key Elements:**  Quickly scan the code for imports, class definitions, and method names. This gives a high-level overview:
    * **Imports:**  `os`, `typing`, and imports from within the Meson project (`..mesonlib`, `..dependencies`, etc.). This confirms it's part of Meson and interacts with other Meson components.
    * **Class:** `MesonMain`. This is the central class we need to analyze. The name strongly suggests it's a primary entry point or controller within the Meson interpreter.
    * **Methods:** A long list of methods like `add_install_script_method`, `get_compiler_method`, `override_dependency_method`, etc. These are the individual functionalities this class provides. The names are quite descriptive and provide clues about what each method does.

3. **Analyze Method Functionality (Iterative Process):**  Go through each method and try to understand its purpose. Look at:
    * **Docstrings:**  While not present in this snippet, real-world code often has docstrings explaining the method's purpose and arguments. (The provided comments and type hints serve a similar purpose here).
    * **Method Name:**  The name is usually a good indicator. `add_install_script` clearly deals with adding installation scripts. `get_compiler` fetches compiler information. `override_dependency` allows overriding dependency definitions.
    * **Arguments and Return Types:**  Pay attention to the types of arguments a method takes and what it returns. This clarifies the data flow. The type hints (`T.Tuple`, `NativeKW`, etc.) are very helpful here.
    * **Internal Logic:** Look at what the method *does*. Does it modify the `self.build` object?  Does it interact with the `self.interpreter`? Does it perform any file system operations (like `os.path.join`)?
    * **Decorators:**  Decorators like `@typed_pos_args`, `@typed_kwargs`, `@FeatureNew`, and `@FeatureDeprecated` provide metadata about the method, such as expected arguments and when the feature was added/deprecated. This is valuable for understanding the method's intended use and evolution.

4. **Connect to the Prompts' Questions:** As you understand the methods, start connecting them to the specific questions asked in the prompt:

    * **Functionality:** This is a direct outcome of the method analysis. List the actions each method performs.
    * **Relationship to Reverse Engineering:**  Think about how the *build process* could impact reverse engineering. Methods like `override_dependency` and `override_find_program` stand out. If a build system allows overriding dependencies, this could be used to substitute components with modified versions, which is a technique sometimes used in reverse engineering or security analysis. The presence of install scripts (`add_install_script`) is also relevant as these scripts could potentially be targets for analysis or modification.
    * **Binary/Kernel/Framework Knowledge:** Look for interactions with system-level concepts. The `get_compiler` method and the handling of native builds (`NATIVE_KW`) are related to compiling to specific architectures. The `add_install_script` might involve placing files in system directories. The "cross-build" functionality indicates awareness of different target architectures.
    * **Logical Reasoning (Assumptions/Inputs/Outputs):** For methods that perform some transformation or decision-making, think about what input would lead to what output. For example, `is_cross_build_method` takes no input but returns `True` if the build environment is configured for cross-compilation.
    * **User/Programming Errors:** Consider common mistakes a developer might make when using these methods. Incorrect argument types, passing non-existent files, or trying to override dependencies that are already resolved are examples.
    * **User Operation as Debugging Clue:**  Imagine a scenario where a developer encounters an issue and needs to debug. How would they have reached this part of the Meson code?  They would be running the Meson build system, and the `meson.build` file would contain calls to the methods in `MesonMain`.

5. **Structure the Answer:** Organize the findings logically, addressing each point in the prompt clearly and providing specific examples from the code. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial Overemphasis:**  Initially, I might focus too much on the Frida context. It's important to remember this file is part of *Meson*. The Frida context influences *why* certain features might be present or used, but the code itself is Meson code.
* **Specificity of Examples:**  Instead of saying "it deals with files," be more specific: "It can take `mesonlib.File` objects as arguments and use their paths."
* **Connecting the Dots:** Explicitly state the connection between a method and a concept (e.g., "The `get_compiler_method` is relevant to compiling code, which is a fundamental step in creating binary executables").
* **Review and Clarify:** After drafting the answer, review it to ensure clarity, accuracy, and completeness. Have I addressed all parts of the prompt? Are my examples clear and relevant?

By following these steps, including iterative analysis and connecting the code to the specific questions, we can effectively understand the functionality of this `mesonmain.py` file and its relevance to the broader context of Frida and reverse engineering.
好的，让我们来分析一下 `frida/subprojects/frida-node/releng/meson/mesonbuild/interpreter/mesonmain.py` 这个文件。从路径和内容来看，这是一个属于 Meson 构建系统的 Python 源代码文件，专门用于处理 Frida 项目中 Node.js 相关的构建逻辑。`MesonMain` 类提供了一系列在 Meson 构建脚本中可以调用的函数，用于配置和管理构建过程。

**文件功能列表:**

这个文件定义了 `MesonMain` 类，它包含了一组方法，这些方法对应于 Meson 构建脚本 (`meson.build`) 中可以调用的 `meson.` 开头的内置函数。这些函数的主要功能包括：

1. **添加脚本:**
   - `add_install_script_method`:  添加在安装阶段执行的脚本。
   - `add_postconf_script_method`: 添加在配置后执行的脚本。
   - `add_dist_script_method`: 添加在创建发布包时执行的脚本。

2. **获取目录路径:**
   - `current_source_dir_method`: 获取当前 `meson.build` 文件所在的源代码目录。
   - `current_build_dir_method`: 获取当前 `meson.build` 文件对应的构建目录。
   - `build_root_method` (Deprecated): 获取顶层构建目录。
   - `source_root_method` (Deprecated): 获取顶层源代码目录。
   - `project_source_root_method`: 获取当前项目的源代码根目录。
   - `project_build_root_method`: 获取当前项目的构建根目录。
   - `global_source_root_method`: 获取全局源代码根目录。
   - `global_build_root_method`: 获取全局构建根目录。

3. **构建系统信息:**
   - `backend_method`: 获取当前使用的构建后端 (例如 Ninja, VS 等)。
   - `version_method`: 获取 Meson 的版本。
   - `build_options_method`: 获取用户定义的构建选项。

4. **交叉编译支持:**
   - `is_cross_build_method`: 判断是否是交叉编译。
   - `can_run_host_binaries_method`: 判断主机是否可以运行构建产生的二进制文件（用于交叉编译场景）。
   - `has_exe_wrapper_method` (Deprecated):  判断是否使用了可执行文件包装器 (exe wrapper)。
   - `get_compiler_method`: 获取指定语言的编译器对象。
   - `get_cross_property_method` (Deprecated): 获取交叉编译属性。
   - `get_external_property_method`: 获取外部属性（包括交叉编译属性）。
   - `has_external_property_method`: 检查是否存在指定的外部属性。

5. **依赖管理:**
   - `override_dependency_method`:  覆盖已有的依赖项定义。
   - `override_find_program_method`: 覆盖查找程序的结果。
   - `install_dependency_manifest_method`: 设置依赖清单文件的名称。

6. **项目信息:**
   - `project_name_method`: 获取当前项目的名称。
   - `project_version_method`: 获取当前项目的版本。
   - `project_license_method`: 获取当前项目的许可证信息。
   - `project_license_files_method`: 获取当前项目的许可证文件列表。
   - `is_subproject_method`: 判断当前构建是否是作为子项目进行的。
   - `is_unity_method`: 判断是否启用了 Unity 构建。

7. **环境变量管理:**
   - `add_devenv_method`: 添加需要设置的环境变量。

**与逆向方法的关系 (举例说明):**

`MesonMain.py` 本身是构建系统的代码，直接的逆向方法并不针对它。然而，它所支持的构建过程会产生最终的二进制文件，这些二进制文件才是逆向工程师的目标。`MesonMain.py` 中一些功能间接地与逆向方法相关：

* **`override_dependency_method` 和 `override_find_program_method`:**  在构建过程中，如果使用了这些方法来替换标准的库或工具，逆向工程师分析最终生成的文件时可能会遇到与预期不同的行为。例如，Frida 可能使用 `override_dependency_method` 来替换某些 Node.js 的原生模块，以便在其中插入 Instrumentation 代码。逆向工程师在分析这些被替换的模块时，就需要了解构建过程中发生了哪些替换。

   **举例:** 假设 Frida 的构建脚本中使用了以下代码：

   ```python
   # 假设 'libuv' 是一个 Node.js 的依赖库
   native_libuv = dependency('libuv')
   frida_libuv = find_library('frida-libuv-hooked') # Frida 提供的修改过的 libuv
   meson.override_dependency('libuv', frida_libuv)
   ```

   当逆向工程师分析最终的 Node.js 运行时环境时，会发现 `libuv` 的行为与标准的 `libuv` 不同，因为它被 Frida 提供的 `frida-libuv-hooked` 替换了。理解 Meson 的 `override_dependency_method` 能够帮助逆向工程师理解这种替换的发生。

* **`add_install_script_method`:** 安装脚本可能会执行一些在目标系统上进行配置或修改的操作。逆向工程师可能需要分析这些脚本，以了解目标环境是如何被设置的，或者是否存在任何潜在的后门或植入行为。

   **举例:** Frida 的安装脚本可能包含将 Frida 的 Agent 注入到目标进程的操作。逆向工程师可以通过分析这些脚本来了解注入的具体机制。

**涉及二进制底层，Linux, Android 内核及框架的知识 (举例说明):**

`MesonMain.py` 作为构建系统的一部分，需要处理与目标平台相关的细节。虽然它本身不是直接操作内核或框架的代码，但它提供的功能与这些底层概念密切相关：

* **`get_compiler_method` 和交叉编译相关方法:**  这些方法处理不同目标架构和操作系统的编译过程。Frida 需要支持多种平台 (包括 Linux 和 Android)，因此 Meson 需要能够选择合适的编译器和链接器，并设置正确的编译选项。这涉及到对不同平台 ABI (Application Binary Interface)、系统调用约定、库链接方式等底层知识的理解。

   **举例:**  在为 Android 构建 Frida 时，Meson 需要使用 Android NDK 提供的交叉编译器，并设置正确的 `sysroot` 和目标架构。`get_compiler_method` 允许构建脚本获取这些编译器对象，以便后续的编译步骤可以使用它们。

* **`add_install_script_method`:** 安装脚本经常需要执行一些与操作系统底层相关的操作，例如复制文件到系统目录、设置权限、启动或停止服务等。在 Android 上，这可能涉及到操作 `/system` 分区，与 Android 的 init 系统交互，或者注册服务。

   **举例:** Frida 的安装脚本可能需要在 Android 设备上安装 Frida Server，这需要将可执行文件复制到 `/system/bin` 或其他系统目录，并可能需要修改 SELinux 上下文。

* **`can_run_host_binaries_method`:**  在交叉编译场景中，有时候需要在构建过程中执行主机上的工具。例如，代码生成器或静态分析工具可能运行在构建主机上。这个方法判断主机是否能够执行为目标平台构建的二进制文件（通常不能，除非使用了模拟器或特殊的执行环境）。理解这一点对于构建流程的正确配置至关重要。

**逻辑推理 (假设输入与输出):**

让我们以 `current_source_dir_method` 为例：

* **假设输入:**
    * Meson 构建系统在某个包含 `meson.build` 文件的目录下运行。
    * 当前处理的 `meson.build` 文件位于 `frida/subprojects/frida-node/src` 目录下。
    * 构建命令从顶层目录 `frida` 运行。

* **逻辑推理:**
    * `self.interpreter.environment.source_dir` 将会是顶层源代码目录，即 `frida`。
    * `self.interpreter.subdir` 将会是相对于顶层源代码目录的当前子目录，即 `subprojects/frida-node/src`。
    * 该方法将使用 `os.path.join` 将这两个路径组合起来。

* **预期输出:**  `/path/to/frida/subprojects/frida-node/src` (假设 `/path/to/frida` 是 `frida` 目录的绝对路径)。

**用户或编程常见的使用错误 (举例说明):**

* **`get_compiler_method`:**
    * **错误:** 在 `meson.build` 文件中请求一个不存在的语言的编译器。
    * **用户操作:**  在 `meson.build` 中调用 `meson.get_compiler('foobar')`，但 Meson 并没有名为 'foobar' 的语言的编译器定义。
    * **预期错误:**  `InterpreterException: Tried to access compiler for language "foobar", not specified for <machine type> machine.`

* **`override_dependency_method`:**
    * **错误:**  尝试覆盖一个不存在的依赖项，或者提供了错误的依赖项对象。
    * **用户操作:**  在 `meson.build` 中调用 `meson.override_dependency('nonexistent_lib', some_object)`，但 `nonexistent_lib` 并没有被 `dependency()` 函数声明过。
    * **预期行为:**  根据 Meson 的实现，如果依赖项未被解析，可能会在后续解析时生效。但如果已经解析过，则会报错。

* **`add_install_script_method`:**
    * **错误:**  提供的脚本路径不存在或者没有执行权限。
    * **用户操作:**  在 `meson.build` 中调用 `meson.add_install_script('nonexistent_script.sh')`。
    * **预期错误:**  在安装阶段执行脚本时会失败，Meson 或构建后端会报告错误。

**用户操作如何一步步的到达这里 (作为调试线索):**

当开发者使用 Frida 并且需要构建 Frida 的 Node.js 绑定时，他们会执行以下步骤，这些步骤会触发 Meson 构建系统的工作，并最终执行到 `mesonmain.py` 中的代码：

1. **配置构建:** 开发者通常会创建一个构建目录，并使用 `meson` 命令来配置构建系统，例如：
   ```bash
   mkdir build
   cd build
   meson ..
   ```
   这个命令会读取项目根目录下的 `meson.build` 文件以及其他相关的 `meson.build` 文件（包括 `frida/subprojects/frida-node/meson.build` 等）。

2. **解析 `meson.build` 文件:** Meson 的解释器会读取并解析这些 `meson.build` 文件。当解释器遇到 `meson.` 开头的函数调用时，它会在 `MesonMain` 类中查找对应的方法并执行。例如，如果 `frida/subprojects/frida-node/meson.build` 文件中调用了 `meson.add_install_script(...)`，那么 `mesonmain.py` 中的 `add_install_script_method` 就会被调用。

3. **执行构建:** 配置完成后，开发者会使用构建后端命令来执行实际的构建过程，例如：
   ```bash
   ninja
   ```
   或者
   ```bash
   msbuild  # 如果使用 Visual Studio
   ```
   在这个阶段，Meson 会根据 `meson.build` 中的指令生成构建系统的文件（例如 Ninja 的 `build.ninja`），然后构建后端会读取这些文件并执行编译、链接等操作。

4. **安装:** 构建完成后，开发者可能会执行安装命令：
   ```bash
   ninja install
   ```
   或者
   ```bash
   msbuild -target:INSTALL
   ```
   在这个阶段，`mesonmain.py` 中通过 `add_install_script_method` 添加的安装脚本会被执行。

**调试线索:**

如果开发者在 Frida Node.js 绑定的构建过程中遇到问题，他们可以通过以下方式来追溯到 `mesonmain.py` 的执行：

* **查看 Meson 的输出:** Meson 在配置和构建过程中会输出详细的日志信息，包括执行的 `meson.` 函数调用和相关的参数。开发者可以检查这些日志来了解哪些 `meson.` 函数被调用，以及调用时传递了哪些参数。

* **分析 `meson.build` 文件:**  `meson.build` 文件是构建逻辑的入口。开发者可以分析相关的 `meson.build` 文件，找到可能导致问题的 `meson.` 函数调用。

* **使用 Meson 的调试功能:** Meson 提供了一些调试选项，例如可以输出解析 `meson.build` 文件的过程。虽然直接调试 Python 代码可能不常见，但理解 `meson.build` 的执行流程是关键。

* **断点调试 (高级):**  如果需要深入了解 `mesonmain.py` 的行为，理论上可以使用 Python 调试器（如 `pdb`）来调试 Meson 的执行过程。但这通常只在开发 Meson 本身或进行非常深入的构建问题排查时使用。

总结来说，`frida/subprojects/frida-node/releng/meson/mesonbuild/interpreter/mesonmain.py` 是 Frida 项目中用于 Node.js 绑定构建的关键文件，它提供了 Meson 构建脚本可以调用的各种内置函数，用于配置、管理和执行构建过程。理解这个文件的功能有助于理解 Frida 的构建方式，以及可能存在的与逆向方法相关的方面。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/interpreter/mesonmain.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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