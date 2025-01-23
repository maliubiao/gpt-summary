Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding of the Request:**

The request asks for an analysis of the provided Python code, specifically focusing on:

* **Functionality:** What does this code do?
* **Relevance to Reverse Engineering:** Does it have any connection to reverse engineering techniques?
* **Low-Level Details:** Does it interact with binary, Linux/Android kernels, or frameworks?
* **Logical Reasoning:** Are there any conditional logic sections where we can deduce input/output?
* **Common User Errors:**  What mistakes might a user make when interacting with this code?
* **User Journey (Debugging):** How does a user's action lead to this specific code being executed?
* **Summary of Functionality:** A concise recap of what the code does.

**2. High-Level Overview of the Code:**

Quickly scanning the imports and class definitions reveals a pattern:  This code defines various "Holder" classes and some related helper functions. These "Holder" classes seem to wrap other Meson build system objects (like `ConfigurationData`, `Dependency`, `ExternalProgram`, etc.). There are also utility functions like `extract_required_kwarg` and `extract_search_dirs`.

**3. Deeper Dive into Key Components:**

* **`extract_required_kwarg` and `extract_search_dirs`:** These are clearly utility functions for parsing keyword arguments related to feature requirements and search paths. This suggests the code is involved in configuring and locating dependencies or other build-time requirements.

* **`FeatureOptionHolder`:** This class deals with user-defined features (enabled, disabled, auto). The methods like `enabled_method`, `disabled_method`, `require_method`, etc., indicate functionality for checking and manipulating the state of these features. This is related to build configuration and conditional compilation.

* **`RunProcess`:** This class is very significant. It encapsulates the execution of external commands. The `run_command` method directly uses `subprocess.Popen_safe`. This is a key area for potential reverse engineering connections (executing tools).

* **`EnvironmentVariablesHolder`:**  This manages environment variables. The `set_method`, `append_method`, `prepend_method` functions are for modifying these variables. Environment variables are crucial in build processes and can influence the behavior of compiled binaries.

* **`ConfigurationDataHolder`:**  This handles configuration data (key-value pairs). The methods allow setting, getting, and checking for the presence of configuration values. This data is often embedded into the compiled output or used during the build process.

* **`DependencyHolder`, `ExternalProgramHolder`, `ExternalLibraryHolder`:** These classes represent dependencies, external programs, and libraries, respectively. Their methods provide ways to query information about these entities (found status, paths, versions). Dependencies are a core concept in software development and reverse engineering often involves analyzing dependencies.

* **`MachineHolder`:** This class holds information about the target machine architecture (CPU, OS, endianness). This is essential for cross-compilation and understanding the target environment.

* **Other Holder Classes (`IncludeDirsHolder`, `FileHolder`, etc.):** These represent various build artifacts or configurations within the Meson system.

* **`Test`:** This class defines a test case, including the executable to run, dependencies, arguments, and environment.

**4. Connecting to Reverse Engineering Concepts:**

Now, let's specifically consider the reverse engineering aspects:

* **`RunProcess`:**  This immediately jumps out. Reverse engineers often need to execute binaries or scripts as part of their analysis. This class provides a mechanism for doing so within the Meson build system. Examples would be running disassemblers, debuggers, or custom analysis tools.

* **`DependencyHolder` and `ExternalProgramHolder`:**  Knowing the dependencies and external tools used in building a target is crucial for reverse engineering. These classes provide access to this information. For instance, knowing the version of a library might help identify known vulnerabilities.

* **`ConfigurationDataHolder`:**  Configuration options can significantly affect the behavior of a compiled program. Understanding these settings is important for reverse engineering.

* **`EnvironmentVariablesHolder`:** Environment variables can influence the runtime behavior of programs. Knowing which variables are set during the build can provide valuable insights.

**5. Identifying Low-Level, Kernel, and Framework Connections:**

* **`RunProcess`:** Executing external programs often involves interacting with the operating system at a lower level.
* **`MachineHolder`:**  Information about the kernel and CPU architecture is directly related to low-level system details.
* **Dependencies:** Some dependencies might be low-level libraries or framework components.

**6. Logical Reasoning and Input/Output:**

Focus on methods with conditional logic, such as the `require_method`, `disable_if_method`, and `enable_if_method` in `FeatureOptionHolder`. By tracing the conditions, you can deduce the output based on the input.

**7. Common User Errors:**

Think about how users interact with build systems:

* Incorrect paths in search directories (`extract_search_dirs`).
* Trying to modify configuration data after it's been used (`ConfigurationDataHolder`).
* Providing incorrect arguments to methods.

**8. User Journey (Debugging):**

Imagine a scenario where a build fails. The user might need to inspect the environment variables or configuration data. This could lead them to use Meson's introspection features, which might call upon these classes. Running tests (`Test` class) is another common debugging scenario.

**9. Structuring the Answer:**

Organize the findings into the categories requested (functionality, reverse engineering, low-level, etc.). Provide specific code examples or method names to illustrate the points.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:**  "These 'Holder' classes just seem like wrappers."  **Refinement:** While they are wrappers, they provide specific methods and functionality to interact with the underlying Meson objects. Focus on *what* those methods do.
* **Initial thought:** "Reverse engineering is all about disassembling binaries." **Refinement:** While that's a key part, the *build process* provides valuable context. Understanding how a binary was built (dependencies, tools, configurations) is essential for effective reverse engineering.
* **Focus on the *why*:** Don't just list the methods. Explain *why* those methods are relevant to each category (reverse engineering, low-level, etc.).

By following this systematic approach, you can effectively analyze the given code and generate a comprehensive and informative response.
好的，让我们来分析一下这个 frida 代码文件 `interpreterobjects.py` 的功能。

**文件概述**

这个文件 `interpreterobjects.py` 位于 Frida 工具的子项目 `frida-qml` 的构建系统 Meson 的解释器目录中。它主要定义了 Meson 构建系统中各种对象的“持有者”（Holder）类。这些持有者类封装了 Meson 的内部对象，并为这些对象提供了一组可以在 Meson 构建脚本中调用的方法。

**主要功能归纳**

1. **封装 Meson 内部对象:** 该文件定义了多个以 `*Holder` 结尾的类，例如 `FeatureOptionHolder`，`RunProcess`，`EnvironmentVariablesHolder`，`ConfigurationDataHolder`，`DependencyHolder`，`ExternalProgramHolder` 等。这些类都继承自 `ObjectHolder` 或其子类，用于封装 Meson 构建系统中使用的各种类型的对象，如构建选项、外部程序、依赖项、环境变量、配置数据等。

2. **提供对象的方法:** 每个持有者类都为其封装的 Meson 对象提供了一组可以在 Meson 构建脚本中调用的方法。这些方法允许用户在构建过程中查询或操作这些对象的状态和属性。例如：
   - `FeatureOptionHolder` 提供了 `enabled()`，`disabled()` 等方法来检查构建特性的状态。
   - `RunProcess` 提供了 `returncode()`，`stdout()`，`stderr()` 方法来获取执行外部命令的结果。
   - `DependencyHolder` 提供了 `found()`，`version()`，`get_variable()` 等方法来获取依赖项的信息。

3. **类型检查和参数处理:** 文件中使用了大量的类型注解 (`typing`) 和装饰器 (`@typed_pos_args`, `@typed_kwargs`) 来确保方法调用的参数类型正确，并提供更好的代码可读性和维护性。

4. **支持 Feature Options:** `FeatureOptionHolder` 类专门用于处理 Meson 的特性选项。它允许用户在构建脚本中检查、启用、禁用和修改特性选项的状态。

5. **处理外部命令执行:** `RunProcess` 类负责执行外部命令。它可以捕获命令的输出 (stdout, stderr) 和返回码，并根据需要检查命令是否执行成功。

6. **管理环境变量:** `EnvironmentVariablesHolder` 类用于管理构建过程中的环境变量。它提供了设置、取消设置、追加和前置环境变量的方法。

7. **管理配置数据:** `ConfigurationDataHolder` 类用于管理构建过程中的配置数据。它允许设置、获取和检查配置数据的值。

8. **处理依赖关系:** `DependencyHolder` 类用于处理项目依赖。它提供了获取依赖信息、创建部分依赖等方法。

9. **处理外部程序和库:** `ExternalProgramHolder` 和 `ExternalLibraryHolder` 类分别用于处理外部程序和库。它们提供了检查是否找到、获取路径和版本等方法。

10. **处理测试:** `Test` 类定义了测试用例的结构，包含了测试名称、执行的程序、依赖项、参数、环境变量等信息。

**与逆向方法的关系及举例**

这个文件中的某些功能与逆向工程方法存在一定的关联：

* **执行外部命令 (`RunProcess`):**  在逆向工程过程中，可能需要执行各种工具，例如反汇编器 (如 `objdump`, `ida64` 的命令行版本), 调试器 (如 `gdb`), 二进制分析工具 (如 `strings`, `readelf`) 等。Meson 构建脚本可以使用 `RunProcess` 来执行这些工具，并将它们的输出用于构建过程中的决策或生成报告。

   **举例:** 假设在构建过程中需要检查一个库文件是否包含特定的符号。可以在 Meson 构建脚本中使用 `RunProcess` 执行 `objdump -t` 命令，然后解析其输出来判断符号是否存在。

   ```python
   objdump_cmd = find_program('objdump')
   result = run_command(objdump_cmd, ['-t', library_path])
   if 'desired_symbol' in result.stdout():
       # 执行某些操作
   ```

* **获取外部程序的信息 (`ExternalProgramHolder`):**  在逆向工程的构建过程中，可能依赖于特定的外部工具。`ExternalProgramHolder` 可以用来检查这些工具是否存在，并获取它们的路径和版本。这有助于确保构建环境的正确性。

   **举例:**  在构建一个需要使用特定版本的反汇编器的 Frida 模块时，可以使用 `find_program` 找到该反汇编器，并通过 `ExternalProgramHolder` 获取其版本，以便在构建过程中进行版本检查。

* **处理依赖关系 (`DependencyHolder`):**  逆向工程的目标通常依赖于其他库或组件。`DependencyHolder` 提供的方法可以用来获取这些依赖项的信息，例如它们的路径、包含目录、链接库等。这对于理解目标软件的架构和依赖关系至关重要。

   **举例:**  如果要构建一个与特定版本的 OpenSSL 库交互的 Frida 脚本，可以使用 Meson 的依赖查找机制来找到 OpenSSL，并使用 `DependencyHolder` 获取其头文件路径和链接库，以便正确编译 Frida 模块。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例**

虽然这个文件本身主要是 Meson 构建系统的代码，但它所操作的对象和执行的动作经常涉及到二进制底层、Linux/Android 内核及框架的知识：

* **二进制底层:**
    * **外部程序的执行 (`RunProcess`):** 执行的命令可能直接操作二进制文件，例如链接器 (`ld`)，编译器 (`gcc`, `clang`)，反汇编器等。
    * **依赖项的处理 (`DependencyHolder`):** 处理的依赖项通常是编译后的二进制库文件 (`.so`, `.a`, `.lib`, `.dll`)。
    * **配置数据的设置 (`ConfigurationDataHolder`):** 配置数据可能包含影响二进制生成方式的选项，例如编译优化级别、目标架构等。

* **Linux 内核:**
    * **环境变量 (`EnvironmentVariablesHolder`):** 构建过程中设置的环境变量可能影响编译器和链接器的行为，例如 `PATH` 变量决定了可执行文件的搜索路径。
    * **外部命令 (`RunProcess`):**  在 Linux 环境下执行的命令通常是与操作系统交互的工具，例如操作文件系统的命令 (`cp`, `mkdir`) 或系统工具。
    * **依赖项 (`DependencyHolder`):**  依赖项可能包括 Linux 系统库，例如 `libc`，`pthread` 等。

* **Android 内核及框架:**
    * **交叉编译:**  Frida 经常被用于 Android 平台的逆向工程。Meson 构建系统需要处理针对 Android 平台的交叉编译。`MachineHolder` 类存储了目标机器的信息，这对于交叉编译至关重要。
    * **Android NDK:**  构建 Frida 在 Android 上使用的组件可能需要使用 Android NDK (Native Development Kit)，涉及 Android 特有的构建工具链和库。
    * **Android Framework:**  逆向分析 Android 应用可能涉及到与 Android Framework 的交互。构建 Frida 模块可能需要链接到 Android Framework 提供的库。

**逻辑推理及假设输入与输出**

让我们以 `FeatureOptionHolder` 的 `require_method` 为例：

**假设输入:**
- `self`: 一个 `FeatureOptionHolder` 实例，假设其封装的 `UserFeatureOption` 的 `name` 为 "my_feature"，当前 `value` 为 "auto"。
- `args`: `(False,)`  (布尔值 `False`)
- `kwargs`: `{'error_message': 'This feature is mandatory'}`

**逻辑推理:**
1. `require_method` 接收一个布尔参数 `condition`（对应 `args[0]`，即 `False`）。
2. `_disable_if` 方法被调用，传入 `not condition` (即 `True`) 和 `error_message`。
3. 由于 `condition` 是 `False`， `not condition` 为 `True`，所以会进入 `if condition:` 分支。
4. 由于当前 `value` 是 "auto"，不会抛出异常。
5. 返回 `self.as_disabled()` 的结果。

**预期输出:**
- 返回一个新的 `UserFeatureOption` 对象，该对象是原始 `UserFeatureOption` 的深拷贝，但其 `value` 被设置为 "disabled"。

**用户或编程常见的使用错误及举例**

* **尝试在配置对象被使用后修改其值 (`ConfigurationDataHolder`):** 一旦一个 `ConfigurationDataHolder` 对象被用于生成构建文件，就不能再修改其值。尝试这样做会导致 `InterpreterException`。

   **举例:**
   ```python
   config_data = configuration_data()
   config_data.set('my_option', 'initial_value')
   executable('my_program', 'source.c', config_data: config_data)
   config_data.set('my_option', 'new_value')  # 错误：在 config_data 被使用后尝试修改
   ```

* **为 `run_command` 提供非绝对路径的搜索目录 (`extract_search_dirs`):** `extract_search_dirs` 检查提供的目录是否是绝对路径。如果不是，会抛出 `InvalidCode` 异常。

   **举例:**
   ```python
   search_dirs = extract_search_dirs(dirs: ['relative/path']) # 错误：提供了相对路径
   ```

* **`dependency.get_pkgconfig_variable` 使用了错误的依赖类型 (`DependencyHolder`):**  `get_pkgconfig_variable` 方法只能用于 `PkgConfigDependency` 类型的依赖。如果用于其他类型的依赖，会抛出 `InvalidArguments` 异常。

   **举例:**
   ```python
   dep = declare_dependency(headers: include_directories('include'))
   var = dep.get_pkgconfig_variable('some_variable') # 错误：dep 不是 PkgConfigDependency
   ```

**用户操作是如何一步步的到达这里，作为调试线索**

1. **编写 `meson.build` 文件:** 用户开始编写或修改项目的 `meson.build` 文件，该文件描述了项目的构建过程。
2. **使用 Meson 函数:** 在 `meson.build` 文件中，用户会调用 Meson 提供的各种函数，例如 `feature_option`, `run_command`, `environment`, `configuration_data`, `dependency`, `find_program` 等。
3. **Meson 解释器执行:** 当用户运行 `meson setup builddir` 命令时，Meson 解释器会读取并执行 `meson.build` 文件。
4. **创建持有者对象:** 当解释器遇到需要操作特定 Meson 对象（如特性选项、外部命令等）的函数调用时，就会创建对应的持有者对象（如 `FeatureOptionHolder`, `RunProcess` 实例）。
5. **调用持有者方法:** 用户在 `meson.build` 中调用的方法会映射到持有者对象的方法上。例如，`feature_option('my_feature').enabled()` 会调用 `FeatureOptionHolder` 实例的 `enabled_method`。
6. **执行底层操作:** 持有者对象的方法会执行相应的底层操作，例如执行外部命令、查询依赖信息、修改配置数据等。

**作为调试线索:** 如果在 Meson 构建过程中出现错误，例如找不到程序、依赖项缺失、配置错误等，查看涉及到的 Meson 函数调用以及相关的持有者对象的方法执行情况，可以帮助定位问题。例如：

- 如果 `run_command` 失败，可以检查 `RunProcess` 对象的 `returncode`，`stdout`，`stderr` 来获取命令执行的详细信息。
- 如果依赖项查找失败，可以检查 `DependencyHolder` 对象的 `found()` 方法返回值以及相关的错误信息。
- 如果配置数据设置不正确，可以检查 `ConfigurationDataHolder` 对象中存储的值。

**总结**

`interpreterobjects.py` 文件是 Frida 构建系统 Meson 解释器的核心组成部分，它定义了用于封装和操作各种 Meson 内部对象的持有者类。这些类为 Meson 构建脚本提供了强大的功能，包括处理构建选项、执行外部命令、管理环境变量和配置数据、处理依赖关系等。这些功能在软件构建过程中至关重要，并且与逆向工程实践中使用的工具和技术存在一定的关联。理解这个文件的功能有助于深入理解 Frida 的构建过程，并能更好地调试和扩展 Frida 的功能。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/interpreterobjects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
from __future__ import annotations
import os
import shlex
import subprocess
import copy
import textwrap

from pathlib import Path, PurePath

from .. import mesonlib
from .. import coredata
from .. import build
from .. import mlog

from ..modules import ModuleReturnValue, ModuleObject, ModuleState, ExtensionModule
from ..backend.backends import TestProtocol
from ..interpreterbase import (
                               ContainerTypeInfo, KwargInfo, MesonOperator,
                               MesonInterpreterObject, ObjectHolder, MutableInterpreterObject,
                               FeatureNew, FeatureDeprecated,
                               typed_pos_args, typed_kwargs, typed_operator,
                               noArgsFlattening, noPosargs, noKwargs, unholder_return,
                               flatten, resolve_second_level_holders, InterpreterException, InvalidArguments, InvalidCode)
from ..interpreter.type_checking import NoneType, ENV_KW, ENV_SEPARATOR_KW, PKGCONFIG_DEFINE_KW
from ..dependencies import Dependency, ExternalLibrary, InternalDependency
from ..programs import ExternalProgram
from ..mesonlib import HoldableObject, OptionKey, listify, Popen_safe

import typing as T

if T.TYPE_CHECKING:
    from . import kwargs
    from ..cmake.interpreter import CMakeInterpreter
    from ..envconfig import MachineInfo
    from ..interpreterbase import FeatureCheckBase, InterpreterObject, SubProject, TYPE_var, TYPE_kwargs, TYPE_nvar, TYPE_nkwargs
    from .interpreter import Interpreter

    from typing_extensions import TypedDict

    class EnvironmentSeparatorKW(TypedDict):

        separator: str

_ERROR_MSG_KW: KwargInfo[T.Optional[str]] = KwargInfo('error_message', (str, NoneType))


def extract_required_kwarg(kwargs: 'kwargs.ExtractRequired',
                           subproject: 'SubProject',
                           feature_check: T.Optional[FeatureCheckBase] = None,
                           default: bool = True) -> T.Tuple[bool, bool, T.Optional[str]]:
    val = kwargs.get('required', default)
    disabled = False
    required = False
    feature: T.Optional[str] = None
    if isinstance(val, coredata.UserFeatureOption):
        if not feature_check:
            feature_check = FeatureNew('User option "feature"', '0.47.0')
        feature_check.use(subproject)
        feature = val.name
        if val.is_disabled():
            disabled = True
        elif val.is_enabled():
            required = True
    elif isinstance(val, bool):
        required = val
    else:
        raise InterpreterException('required keyword argument must be boolean or a feature option')

    # Keep boolean value in kwargs to simplify other places where this kwarg is
    # checked.
    # TODO: this should be removed, and those callers should learn about FeatureOptions
    kwargs['required'] = required

    return disabled, required, feature

def extract_search_dirs(kwargs: 'kwargs.ExtractSearchDirs') -> T.List[str]:
    search_dirs_str = mesonlib.stringlistify(kwargs.get('dirs', []))
    search_dirs = [Path(d).expanduser() for d in search_dirs_str]
    for d in search_dirs:
        if mesonlib.is_windows() and d.root.startswith('\\'):
            # a Unix-path starting with `/` that is not absolute on Windows.
            # discard without failing for end-user ease of cross-platform directory arrays
            continue
        if not d.is_absolute():
            raise InvalidCode(f'Search directory {d} is not an absolute path.')
    return [str(s) for s in search_dirs]

class FeatureOptionHolder(ObjectHolder[coredata.UserFeatureOption]):
    def __init__(self, option: coredata.UserFeatureOption, interpreter: 'Interpreter'):
        super().__init__(option, interpreter)
        if option and option.is_auto():
            # TODO: we need to cast here because options is not a TypedDict
            auto = T.cast('coredata.UserFeatureOption', self.env.coredata.options[OptionKey('auto_features')])
            self.held_object = copy.copy(auto)
            self.held_object.name = option.name
        self.methods.update({'enabled': self.enabled_method,
                             'disabled': self.disabled_method,
                             'allowed': self.allowed_method,
                             'auto': self.auto_method,
                             'require': self.require_method,
                             'disable_auto_if': self.disable_auto_if_method,
                             'enable_auto_if': self.enable_auto_if_method,
                             'disable_if': self.disable_if_method,
                             'enable_if': self.enable_if_method,
                             })

    @property
    def value(self) -> str:
        return 'disabled' if not self.held_object else self.held_object.value

    def as_disabled(self) -> coredata.UserFeatureOption:
        disabled = copy.deepcopy(self.held_object)
        disabled.value = 'disabled'
        return disabled

    def as_enabled(self) -> coredata.UserFeatureOption:
        enabled = copy.deepcopy(self.held_object)
        enabled.value = 'enabled'
        return enabled

    @noPosargs
    @noKwargs
    def enabled_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> bool:
        return self.value == 'enabled'

    @noPosargs
    @noKwargs
    def disabled_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> bool:
        return self.value == 'disabled'

    @noPosargs
    @noKwargs
    @FeatureNew('feature_option.allowed()', '0.59.0')
    def allowed_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> bool:
        return self.value != 'disabled'

    @noPosargs
    @noKwargs
    def auto_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> bool:
        return self.value == 'auto'

    def _disable_if(self, condition: bool, message: T.Optional[str]) -> coredata.UserFeatureOption:
        if not condition:
            return copy.deepcopy(self.held_object)

        if self.value == 'enabled':
            err_msg = f'Feature {self.held_object.name} cannot be enabled'
            if message:
                err_msg += f': {message}'
            raise InterpreterException(err_msg)
        return self.as_disabled()

    @FeatureNew('feature_option.require()', '0.59.0')
    @typed_pos_args('feature_option.require', bool)
    @typed_kwargs(
        'feature_option.require',
        _ERROR_MSG_KW,
    )
    def require_method(self, args: T.Tuple[bool], kwargs: 'kwargs.FeatureOptionRequire') -> coredata.UserFeatureOption:
        return self._disable_if(not args[0], kwargs['error_message'])

    @FeatureNew('feature_option.disable_if()', '1.1.0')
    @typed_pos_args('feature_option.disable_if', bool)
    @typed_kwargs(
        'feature_option.disable_if',
        _ERROR_MSG_KW,
    )
    def disable_if_method(self, args: T.Tuple[bool], kwargs: 'kwargs.FeatureOptionRequire') -> coredata.UserFeatureOption:
        return self._disable_if(args[0], kwargs['error_message'])

    @FeatureNew('feature_option.enable_if()', '1.1.0')
    @typed_pos_args('feature_option.enable_if', bool)
    @typed_kwargs(
        'feature_option.enable_if',
        _ERROR_MSG_KW,
    )
    def enable_if_method(self, args: T.Tuple[bool], kwargs: 'kwargs.FeatureOptionRequire') -> coredata.UserFeatureOption:
        if not args[0]:
            return copy.deepcopy(self.held_object)

        if self.value == 'disabled':
            err_msg = f'Feature {self.held_object.name} cannot be disabled'
            if kwargs['error_message']:
                err_msg += f': {kwargs["error_message"]}'
            raise InterpreterException(err_msg)
        return self.as_enabled()

    @FeatureNew('feature_option.disable_auto_if()', '0.59.0')
    @noKwargs
    @typed_pos_args('feature_option.disable_auto_if', bool)
    def disable_auto_if_method(self, args: T.Tuple[bool], kwargs: TYPE_kwargs) -> coredata.UserFeatureOption:
        return copy.deepcopy(self.held_object) if self.value != 'auto' or not args[0] else self.as_disabled()

    @FeatureNew('feature_option.enable_auto_if()', '1.1.0')
    @noKwargs
    @typed_pos_args('feature_option.enable_auto_if', bool)
    def enable_auto_if_method(self, args: T.Tuple[bool], kwargs: TYPE_kwargs) -> coredata.UserFeatureOption:
        return self.as_enabled() if self.value == 'auto' and args[0] else copy.deepcopy(self.held_object)


class RunProcess(MesonInterpreterObject):

    def __init__(self,
                 cmd: ExternalProgram,
                 args: T.List[str],
                 env: mesonlib.EnvironmentVariables,
                 source_dir: str,
                 build_dir: str,
                 subdir: str,
                 mesonintrospect: T.List[str],
                 in_builddir: bool = False,
                 check: bool = False,
                 capture: bool = True) -> None:
        super().__init__()
        if not isinstance(cmd, ExternalProgram):
            raise AssertionError('BUG: RunProcess must be passed an ExternalProgram')
        self.capture = capture
        self.returncode, self.stdout, self.stderr = self.run_command(cmd, args, env, source_dir, build_dir, subdir, mesonintrospect, in_builddir, check)
        self.methods.update({'returncode': self.returncode_method,
                             'stdout': self.stdout_method,
                             'stderr': self.stderr_method,
                             })

    def run_command(self,
                    cmd: ExternalProgram,
                    args: T.List[str],
                    env: mesonlib.EnvironmentVariables,
                    source_dir: str,
                    build_dir: str,
                    subdir: str,
                    mesonintrospect: T.List[str],
                    in_builddir: bool,
                    check: bool = False) -> T.Tuple[int, str, str]:
        command_array = cmd.get_command() + args
        menv = {'MESON_SOURCE_ROOT': source_dir,
                'MESON_BUILD_ROOT': build_dir,
                'MESON_SUBDIR': subdir,
                'MESONINTROSPECT': ' '.join([shlex.quote(x) for x in mesonintrospect]),
                }
        if in_builddir:
            cwd = os.path.join(build_dir, subdir)
        else:
            cwd = os.path.join(source_dir, subdir)
        child_env = os.environ.copy()
        child_env.update(menv)
        child_env = env.get_env(child_env)
        stdout = subprocess.PIPE if self.capture else subprocess.DEVNULL
        mlog.debug('Running command:', mesonlib.join_args(command_array))
        try:
            p, o, e = Popen_safe(command_array, stdout=stdout, env=child_env, cwd=cwd)
            if self.capture:
                mlog.debug('--- stdout ---')
                mlog.debug(o)
            else:
                o = ''
                mlog.debug('--- stdout disabled ---')
            mlog.debug('--- stderr ---')
            mlog.debug(e)
            mlog.debug('')

            if check and p.returncode != 0:
                raise InterpreterException('Command `{}` failed with status {}.'.format(mesonlib.join_args(command_array), p.returncode))

            return p.returncode, o, e
        except FileNotFoundError:
            raise InterpreterException('Could not execute command `%s`.' % mesonlib.join_args(command_array))

    @noPosargs
    @noKwargs
    def returncode_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> int:
        return self.returncode

    @noPosargs
    @noKwargs
    def stdout_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.stdout

    @noPosargs
    @noKwargs
    def stderr_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.stderr

class EnvironmentVariablesHolder(ObjectHolder[mesonlib.EnvironmentVariables], MutableInterpreterObject):

    def __init__(self, obj: mesonlib.EnvironmentVariables, interpreter: 'Interpreter'):
        super().__init__(obj, interpreter)
        self.methods.update({'set': self.set_method,
                             'unset': self.unset_method,
                             'append': self.append_method,
                             'prepend': self.prepend_method,
                             })

    def __repr__(self) -> str:
        repr_str = "<{0}: {1}>"
        return repr_str.format(self.__class__.__name__, self.held_object.envvars)

    def __deepcopy__(self, memo: T.Dict[str, object]) -> 'EnvironmentVariablesHolder':
        # Avoid trying to copy the interpreter
        return EnvironmentVariablesHolder(copy.deepcopy(self.held_object), self.interpreter)

    def warn_if_has_name(self, name: str) -> None:
        # Multiple append/prepend operations was not supported until 0.58.0.
        if self.held_object.has_name(name):
            m = f'Overriding previous value of environment variable {name!r} with a new one'
            FeatureNew(m, '0.58.0').use(self.subproject, self.current_node)

    @typed_pos_args('environment.set', str, varargs=str, min_varargs=1)
    @typed_kwargs('environment.set', ENV_SEPARATOR_KW)
    def set_method(self, args: T.Tuple[str, T.List[str]], kwargs: 'EnvironmentSeparatorKW') -> None:
        name, values = args
        self.held_object.set(name, values, kwargs['separator'])

    @FeatureNew('environment.unset', '1.4.0')
    @typed_pos_args('environment.unset', str)
    @noKwargs
    def unset_method(self, args: T.Tuple[str], kwargs: TYPE_kwargs) -> None:
        self.held_object.unset(args[0])

    @typed_pos_args('environment.append', str, varargs=str, min_varargs=1)
    @typed_kwargs('environment.append', ENV_SEPARATOR_KW)
    def append_method(self, args: T.Tuple[str, T.List[str]], kwargs: 'EnvironmentSeparatorKW') -> None:
        name, values = args
        self.warn_if_has_name(name)
        self.held_object.append(name, values, kwargs['separator'])

    @typed_pos_args('environment.prepend', str, varargs=str, min_varargs=1)
    @typed_kwargs('environment.prepend', ENV_SEPARATOR_KW)
    def prepend_method(self, args: T.Tuple[str, T.List[str]], kwargs: 'EnvironmentSeparatorKW') -> None:
        name, values = args
        self.warn_if_has_name(name)
        self.held_object.prepend(name, values, kwargs['separator'])


_CONF_DATA_SET_KWS: KwargInfo[T.Optional[str]] = KwargInfo('description', (str, NoneType))


class ConfigurationDataHolder(ObjectHolder[build.ConfigurationData], MutableInterpreterObject):

    def __init__(self, obj: build.ConfigurationData, interpreter: 'Interpreter'):
        super().__init__(obj, interpreter)
        self.methods.update({'set': self.set_method,
                             'set10': self.set10_method,
                             'set_quoted': self.set_quoted_method,
                             'has': self.has_method,
                             'get': self.get_method,
                             'keys': self.keys_method,
                             'get_unquoted': self.get_unquoted_method,
                             'merge_from': self.merge_from_method,
                             })

    def __deepcopy__(self, memo: T.Dict) -> 'ConfigurationDataHolder':
        return ConfigurationDataHolder(copy.deepcopy(self.held_object), self.interpreter)

    def is_used(self) -> bool:
        return self.held_object.used

    def __check_used(self) -> None:
        if self.is_used():
            raise InterpreterException("Can not set values on configuration object that has been used.")

    @typed_pos_args('configuration_data.set', str, (str, int, bool))
    @typed_kwargs('configuration_data.set', _CONF_DATA_SET_KWS)
    def set_method(self, args: T.Tuple[str, T.Union[str, int, bool]], kwargs: 'kwargs.ConfigurationDataSet') -> None:
        self.__check_used()
        self.held_object.values[args[0]] = (args[1], kwargs['description'])

    @typed_pos_args('configuration_data.set_quoted', str, str)
    @typed_kwargs('configuration_data.set_quoted', _CONF_DATA_SET_KWS)
    def set_quoted_method(self, args: T.Tuple[str, str], kwargs: 'kwargs.ConfigurationDataSet') -> None:
        self.__check_used()
        escaped_val = '\\"'.join(args[1].split('"'))
        self.held_object.values[args[0]] = (f'"{escaped_val}"', kwargs['description'])

    @typed_pos_args('configuration_data.set10', str, (int, bool))
    @typed_kwargs('configuration_data.set10', _CONF_DATA_SET_KWS)
    def set10_method(self, args: T.Tuple[str, T.Union[int, bool]], kwargs: 'kwargs.ConfigurationDataSet') -> None:
        self.__check_used()
        # bool is a subclass of int, so we need to check for bool explicitly.
        # We already have typed_pos_args checking that this is either a bool or
        # an int.
        if not isinstance(args[1], bool):
            mlog.deprecation('configuration_data.set10 with number. The `set10` '
                             'method should only be used with booleans',
                             location=self.interpreter.current_node)
            if args[1] < 0:
                mlog.warning('Passing a number that is less than 0 may not have the intended result, '
                             'as meson will treat all non-zero values as true.',
                             location=self.interpreter.current_node)
        self.held_object.values[args[0]] = (int(args[1]), kwargs['description'])

    @typed_pos_args('configuration_data.has', (str, int, bool))
    @noKwargs
    def has_method(self, args: T.Tuple[T.Union[str, int, bool]], kwargs: TYPE_kwargs) -> bool:
        return args[0] in self.held_object.values

    @FeatureNew('configuration_data.get()', '0.38.0')
    @typed_pos_args('configuration_data.get', str, optargs=[(str, int, bool)])
    @noKwargs
    def get_method(self, args: T.Tuple[str, T.Optional[T.Union[str, int, bool]]],
                   kwargs: TYPE_kwargs) -> T.Union[str, int, bool]:
        name = args[0]
        if name in self.held_object:
            return self.held_object.get(name)[0]
        elif args[1] is not None:
            return args[1]
        raise InterpreterException(f'Entry {name} not in configuration data.')

    @FeatureNew('configuration_data.get_unquoted()', '0.44.0')
    @typed_pos_args('configuration_data.get_unquoted', str, optargs=[(str, int, bool)])
    @noKwargs
    def get_unquoted_method(self, args: T.Tuple[str, T.Optional[T.Union[str, int, bool]]],
                            kwargs: TYPE_kwargs) -> T.Union[str, int, bool]:
        name = args[0]
        if name in self.held_object:
            val = self.held_object.get(name)[0]
        elif args[1] is not None:
            val = args[1]
        else:
            raise InterpreterException(f'Entry {name} not in configuration data.')
        if isinstance(val, str) and val[0] == '"' and val[-1] == '"':
            return val[1:-1]
        return val

    def get(self, name: str) -> T.Tuple[T.Union[str, int, bool], T.Optional[str]]:
        return self.held_object.values[name]

    @FeatureNew('configuration_data.keys()', '0.57.0')
    @noPosargs
    @noKwargs
    def keys_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> T.List[str]:
        return sorted(self.keys())

    def keys(self) -> T.List[str]:
        return list(self.held_object.values.keys())

    @typed_pos_args('configuration_data.merge_from', build.ConfigurationData)
    @noKwargs
    def merge_from_method(self, args: T.Tuple[build.ConfigurationData], kwargs: TYPE_kwargs) -> None:
        from_object = args[0]
        self.held_object.values.update(from_object.values)


_PARTIAL_DEP_KWARGS = [
    KwargInfo('compile_args', bool, default=False),
    KwargInfo('link_args',    bool, default=False),
    KwargInfo('links',        bool, default=False),
    KwargInfo('includes',     bool, default=False),
    KwargInfo('sources',      bool, default=False),
]

class DependencyHolder(ObjectHolder[Dependency]):
    def __init__(self, dep: Dependency, interpreter: 'Interpreter'):
        super().__init__(dep, interpreter)
        self.methods.update({'found': self.found_method,
                             'type_name': self.type_name_method,
                             'version': self.version_method,
                             'name': self.name_method,
                             'get_pkgconfig_variable': self.pkgconfig_method,
                             'get_configtool_variable': self.configtool_method,
                             'get_variable': self.variable_method,
                             'partial_dependency': self.partial_dependency_method,
                             'include_type': self.include_type_method,
                             'as_system': self.as_system_method,
                             'as_link_whole': self.as_link_whole_method,
                             })

    def found(self) -> bool:
        return self.found_method([], {})

    @noPosargs
    @noKwargs
    def type_name_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.type_name

    @noPosargs
    @noKwargs
    def found_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> bool:
        if self.held_object.type_name == 'internal':
            return True
        return self.held_object.found()

    @noPosargs
    @noKwargs
    def version_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.get_version()

    @noPosargs
    @noKwargs
    def name_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.get_name()

    @FeatureDeprecated('dependency.get_pkgconfig_variable', '0.56.0',
                       'use dependency.get_variable(pkgconfig : ...) instead')
    @typed_pos_args('dependency.get_pkgconfig_variable', str)
    @typed_kwargs(
        'dependency.get_pkgconfig_variable',
        KwargInfo('default', str, default=''),
        PKGCONFIG_DEFINE_KW.evolve(name='define_variable')
    )
    def pkgconfig_method(self, args: T.Tuple[str], kwargs: 'kwargs.DependencyPkgConfigVar') -> str:
        from ..dependencies.pkgconfig import PkgConfigDependency
        if not isinstance(self.held_object, PkgConfigDependency):
            raise InvalidArguments(f'{self.held_object.get_name()!r} is not a pkgconfig dependency')
        if kwargs['define_variable'] and len(kwargs['define_variable']) > 1:
            FeatureNew.single_use('dependency.get_pkgconfig_variable keyword argument "define_variable"  with more than one pair',
                                  '1.3.0', self.subproject, location=self.current_node)
        return self.held_object.get_variable(
            pkgconfig=args[0],
            default_value=kwargs['default'],
            pkgconfig_define=kwargs['define_variable'],
        )

    @FeatureNew('dependency.get_configtool_variable', '0.44.0')
    @FeatureDeprecated('dependency.get_configtool_variable', '0.56.0',
                       'use dependency.get_variable(configtool : ...) instead')
    @noKwargs
    @typed_pos_args('dependency.get_config_tool_variable', str)
    def configtool_method(self, args: T.Tuple[str], kwargs: TYPE_kwargs) -> str:
        from ..dependencies.configtool import ConfigToolDependency
        if not isinstance(self.held_object, ConfigToolDependency):
            raise InvalidArguments(f'{self.held_object.get_name()!r} is not a config-tool dependency')
        return self.held_object.get_variable(
            configtool=args[0],
            default_value='',
        )

    @FeatureNew('dependency.partial_dependency', '0.46.0')
    @noPosargs
    @typed_kwargs('dependency.partial_dependency', *_PARTIAL_DEP_KWARGS)
    def partial_dependency_method(self, args: T.List[TYPE_nvar], kwargs: 'kwargs.DependencyMethodPartialDependency') -> Dependency:
        pdep = self.held_object.get_partial_dependency(**kwargs)
        return pdep

    @FeatureNew('dependency.get_variable', '0.51.0')
    @typed_pos_args('dependency.get_variable', optargs=[str])
    @typed_kwargs(
        'dependency.get_variable',
        KwargInfo('cmake', (str, NoneType)),
        KwargInfo('pkgconfig', (str, NoneType)),
        KwargInfo('configtool', (str, NoneType)),
        KwargInfo('internal', (str, NoneType), since='0.54.0'),
        KwargInfo('default_value', (str, NoneType)),
        PKGCONFIG_DEFINE_KW,
    )
    def variable_method(self, args: T.Tuple[T.Optional[str]], kwargs: 'kwargs.DependencyGetVariable') -> str:
        default_varname = args[0]
        if default_varname is not None:
            FeatureNew('Positional argument to dependency.get_variable()', '0.58.0').use(self.subproject, self.current_node)
        if kwargs['pkgconfig_define'] and len(kwargs['pkgconfig_define']) > 1:
            FeatureNew.single_use('dependency.get_variable keyword argument "pkgconfig_define" with more than one pair',
                                  '1.3.0', self.subproject, 'In previous versions, this silently returned a malformed value.',
                                  self.current_node)
        return self.held_object.get_variable(
            cmake=kwargs['cmake'] or default_varname,
            pkgconfig=kwargs['pkgconfig'] or default_varname,
            configtool=kwargs['configtool'] or default_varname,
            internal=kwargs['internal'] or default_varname,
            default_value=kwargs['default_value'],
            pkgconfig_define=kwargs['pkgconfig_define'],
        )

    @FeatureNew('dependency.include_type', '0.52.0')
    @noPosargs
    @noKwargs
    def include_type_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.get_include_type()

    @FeatureNew('dependency.as_system', '0.52.0')
    @noKwargs
    @typed_pos_args('dependency.as_system', optargs=[str])
    def as_system_method(self, args: T.Tuple[T.Optional[str]], kwargs: TYPE_kwargs) -> Dependency:
        return self.held_object.generate_system_dependency(args[0] or 'system')

    @FeatureNew('dependency.as_link_whole', '0.56.0')
    @noKwargs
    @noPosargs
    def as_link_whole_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> Dependency:
        if not isinstance(self.held_object, InternalDependency):
            raise InterpreterException('as_link_whole method is only supported on declare_dependency() objects')
        new_dep = self.held_object.generate_link_whole_dependency()
        return new_dep

_EXTPROG = T.TypeVar('_EXTPROG', bound=ExternalProgram)

class _ExternalProgramHolder(ObjectHolder[_EXTPROG]):
    def __init__(self, ep: _EXTPROG, interpreter: 'Interpreter') -> None:
        super().__init__(ep, interpreter)
        self.methods.update({'found': self.found_method,
                             'path': self.path_method,
                             'version': self.version_method,
                             'full_path': self.full_path_method})

    @noPosargs
    @noKwargs
    def found_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> bool:
        return self.found()

    @noPosargs
    @noKwargs
    @FeatureDeprecated('ExternalProgram.path', '0.55.0',
                       'use ExternalProgram.full_path() instead')
    def path_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self._full_path()

    @noPosargs
    @noKwargs
    @FeatureNew('ExternalProgram.full_path', '0.55.0')
    def full_path_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self._full_path()

    def _full_path(self) -> str:
        if not self.found():
            raise InterpreterException('Unable to get the path of a not-found external program')
        path = self.held_object.get_path()
        assert path is not None
        return path

    @noPosargs
    @noKwargs
    @FeatureNew('ExternalProgram.version', '0.62.0')
    def version_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        if not self.found():
            raise InterpreterException('Unable to get the version of a not-found external program')
        try:
            return self.held_object.get_version(self.interpreter)
        except mesonlib.MesonException:
            return 'unknown'

    def found(self) -> bool:
        return self.held_object.found()

class ExternalProgramHolder(_ExternalProgramHolder[ExternalProgram]):
    pass

class ExternalLibraryHolder(ObjectHolder[ExternalLibrary]):
    def __init__(self, el: ExternalLibrary, interpreter: 'Interpreter'):
        super().__init__(el, interpreter)
        self.methods.update({'found': self.found_method,
                             'type_name': self.type_name_method,
                             'partial_dependency': self.partial_dependency_method,
                             })

    @noPosargs
    @noKwargs
    def type_name_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.type_name

    @noPosargs
    @noKwargs
    def found_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> bool:
        return self.held_object.found()

    @FeatureNew('dependency.partial_dependency', '0.46.0')
    @noPosargs
    @typed_kwargs('dependency.partial_dependency', *_PARTIAL_DEP_KWARGS)
    def partial_dependency_method(self, args: T.List[TYPE_nvar], kwargs: 'kwargs.DependencyMethodPartialDependency') -> Dependency:
        pdep = self.held_object.get_partial_dependency(**kwargs)
        return pdep

# A machine that's statically known from the cross file
class MachineHolder(ObjectHolder['MachineInfo']):
    def __init__(self, machine_info: 'MachineInfo', interpreter: 'Interpreter'):
        super().__init__(machine_info, interpreter)
        self.methods.update({'system': self.system_method,
                             'cpu': self.cpu_method,
                             'cpu_family': self.cpu_family_method,
                             'endian': self.endian_method,
                             'kernel': self.kernel_method,
                             'subsystem': self.subsystem_method,
                             })

    @noPosargs
    @noKwargs
    def cpu_family_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.cpu_family

    @noPosargs
    @noKwargs
    def cpu_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.cpu

    @noPosargs
    @noKwargs
    def system_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.system

    @noPosargs
    @noKwargs
    def endian_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.endian

    @noPosargs
    @noKwargs
    def kernel_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        if self.held_object.kernel is not None:
            return self.held_object.kernel
        raise InterpreterException('Kernel not defined or could not be autodetected.')

    @noPosargs
    @noKwargs
    def subsystem_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        if self.held_object.subsystem is not None:
            return self.held_object.subsystem
        raise InterpreterException('Subsystem not defined or could not be autodetected.')


class IncludeDirsHolder(ObjectHolder[build.IncludeDirs]):
    pass

class FileHolder(ObjectHolder[mesonlib.File]):
    def __init__(self, file: mesonlib.File, interpreter: 'Interpreter'):
        super().__init__(file, interpreter)
        self.methods.update({'full_path': self.full_path_method,
                             })

    @noPosargs
    @noKwargs
    @FeatureNew('file.full_path', '1.4.0')
    def full_path_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.absolute_path(self.env.source_dir, self.env.build_dir)

class HeadersHolder(ObjectHolder[build.Headers]):
    pass

class DataHolder(ObjectHolder[build.Data]):
    pass

class SymlinkDataHolder(ObjectHolder[build.SymlinkData]):
    pass

class InstallDirHolder(ObjectHolder[build.InstallDir]):
    pass

class ManHolder(ObjectHolder[build.Man]):
    pass

class EmptyDirHolder(ObjectHolder[build.EmptyDir]):
    pass

class GeneratedObjectsHolder(ObjectHolder[build.ExtractedObjects]):
    pass

class Test(MesonInterpreterObject):
    def __init__(self, name: str, project: str, suite: T.List[str],
                 exe: T.Union[ExternalProgram, build.Executable, build.CustomTarget, build.CustomTargetIndex],
                 depends: T.List[T.Union[build.CustomTarget, build.BuildTarget]],
                 is_parallel: bool,
                 cmd_args: T.List[T.Union[str, mesonlib.File, build.Target]],
                 env: mesonlib.EnvironmentVariables,
                 should_fail: bool, timeout: int, workdir: T.Optional[str], protocol: str,
                 priority: int, verbose: bool):
```