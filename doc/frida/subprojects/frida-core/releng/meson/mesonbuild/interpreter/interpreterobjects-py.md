Response:
Let's break down the thought process for analyzing this Python code snippet from Frida.

**1. Understanding the Goal:**

The request asks for a functional breakdown of the provided Python code, focusing on aspects relevant to reverse engineering, low-level operations, kernel/framework interactions, logical reasoning, potential user errors, and debugging. The key is to identify *what* the code does and *why* it matters in the context of a dynamic instrumentation tool like Frida.

**2. Initial Scan and Keyword Spotting:**

A quick read-through reveals several important keywords and patterns:

* **Object-Oriented Structure:**  The code defines many classes (`FeatureOptionHolder`, `RunProcess`, `EnvironmentVariablesHolder`, etc.), suggesting it's built around representing different entities and their behaviors.
* **`mesonbuild`:** This immediately tells us it's part of Meson, a build system. Frida uses Meson for its build process.
* **`interpreterobjects.py`:** This suggests these classes are objects used within Meson's interpretation of the build definition (likely `meson.build` files).
* **`ExternalProgram`, `Dependency`, `ConfigurationData`:** These represent key concepts in a build system: external tools, library dependencies, and build configuration settings.
* **`run_command`:**  This clearly indicates the ability to execute external processes.
* **`EnvironmentVariables`:**  This relates to manipulating the environment in which processes run.
* **`FeatureOption`:**  This points to configurable build features.
* **`__init__`, methods like `enabled_method`, `set_method`, `found_method`:** These are standard Python class elements for initialization and defining behavior.
* **Type Hinting (`T.List`, `T.Tuple`, `TYPE_var`):** This improves code readability and helps with static analysis.
* **Decorators (`@noPosargs`, `@typed_pos_args`):** These are part of Meson's internal structure for defining how function arguments are handled in the build language.
* **Mentions of "reverse engineering" (in the prompt):** This guides the analysis towards features relevant to dynamic analysis and manipulation.

**3. Categorizing Functionality:**

Based on the initial scan, I started grouping the classes and methods by their apparent purpose:

* **Feature Handling:**  `FeatureOptionHolder`, `extract_required_kwarg`. This is about enabling/disabling optional parts of the build.
* **Process Execution:** `RunProcess`. Crucial for running external tools during the build.
* **Environment Management:** `EnvironmentVariablesHolder`. Important for setting up the execution environment of built programs and build tools.
* **Configuration Management:** `ConfigurationDataHolder`. Storing and accessing build settings.
* **Dependency Management:** `DependencyHolder`, `ExternalLibraryHolder`. Dealing with libraries the project relies on.
* **External Program Handling:** `ExternalProgramHolder`. Finding and interacting with external executables.
* **System Information:** `MachineHolder`. Gathering information about the build and target machines.
* **Build Artifact Representation:** `IncludeDirsHolder`, `FileHolder`, `HeadersHolder`, etc. Representing the output of the build process.
* **Testing:** The `Test` class (though incomplete in the snippet) indicates how tests are defined and executed.

**4. Identifying Relevance to Reverse Engineering:**

Now, the crucial step is connecting these functionalities to reverse engineering:

* **`RunProcess`:**  This is a direct link. Frida needs to execute processes it's going to instrument. Reverse engineers often run target applications. The ability to control the environment (`env`) is also key.
* **`DependencyHolder` and `ExternalProgramHolder`:**  Knowing about dependencies and external tools used in the build can be helpful in understanding the target application's structure and potential attack surfaces. During reverse engineering, one might encounter dependencies or use external disassemblers/debuggers.
* **`ConfigurationDataHolder`:** Build options can reveal important information about how the target was compiled (e.g., debugging symbols, optimization levels).
* **The general concept of "objects" representing build artifacts:**  While not directly used *during* reverse engineering of a final binary, understanding how Frida *builds* its components can provide insight into its internal workings, which a reverse engineer of Frida itself might need.

**5. Identifying Relevance to Low-Level/Kernel/Framework:**

* **`RunProcess`:** Interacting with the operating system to execute processes is a low-level operation. On Android, this might involve interacting with the Android runtime.
* **`EnvironmentVariablesHolder`:** Environment variables can influence how a program interacts with the OS, potentially affecting system calls or library loading. This is relevant to understanding program behavior at a lower level.
* **`MachineHolder`:** Knowing the target architecture (CPU, endianness, kernel) is essential for reverse engineering.
* **Dependencies on system libraries:** The dependency management aspect touches on how Frida (and the programs it instruments) interacts with the underlying OS and its libraries.

**6. Logical Reasoning (Assumptions and Outputs):**

For each class/method, I considered:

* **What are the inputs?** (Arguments to the methods)
* **What is the expected output?** (Return values)
* **What are the internal logic steps?** (Even without detailed code, the method names often suggest the logic.)
* **What assumptions are made?** (e.g., `ExternalProgram` is found before getting its path).

**7. Potential User Errors:**

I looked for situations where incorrect usage of these objects/methods could lead to errors:

* **Incorrect paths in `extract_search_dirs`**.
* **Trying to modify `ConfigurationData` after it's been used.**
* **Calling methods on non-existent dependencies or external programs.**
* **Incorrect types for arguments to methods.**

**8. Tracing User Operations (Debugging):**

This requires thinking about how a user interacts with Frida and how that interaction might lead to this specific code being executed:

* **Modifying `meson.build`:** Users define their build using Meson's DSL, which gets interpreted, leading to the creation of these objects.
* **Running Meson commands:**  Commands like `meson configure` or `meson compile` trigger the interpretation process.
* **Interacting with Frida's API:** While this code is build-related, understanding how Frida's Python API interacts with its core components provides context.

**9. Iteration and Refinement:**

The initial analysis might not be perfect. I would go back and refine my understanding, looking for more subtle connections and details. For example, the `@FeatureNew` and `@FeatureDeprecated` decorators highlight the evolution of the Meson build system and potential compatibility issues.

**Self-Correction Example During the Process:**

Initially, I might focus too heavily on the direct reverse engineering of the *target* application. Then, I'd realize that this code is about building *Frida* itself. The relevance to reverse engineering comes more from understanding how Frida is constructed and how it interacts with the system during instrumentation. This shift in perspective helps focus the analysis more accurately.

By following this structured approach, combining code reading with domain knowledge (build systems, reverse engineering concepts, operating system fundamentals), and continually asking "why" and "how," I could arrive at the detailed analysis provided in the example answer.
好的，让我们来详细分析一下 `frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/interpreterobjects.py` 这个文件的功能。这是一个 Frida 动态 instrumentation 工具的源代码文件，它主要定义了 Meson 构建系统中用于表示各种构建相关对象的 Python 类。这些类在 Meson 解释 `meson.build` 文件时被实例化，并提供了操作和查询构建信息的接口。

**主要功能归纳:**

这个文件的核心功能是定义了 Meson 解释器中使用的各种对象类型，这些对象代表了构建过程中的不同实体，例如：

1. **构建特性选项 (`FeatureOptionHolder`):**  用于表示用户可配置的构建特性选项，例如是否启用某个功能。
2. **进程执行 (`RunProcess`):**  用于执行外部命令，并捕获其输出和返回码。
3. **环境变量 (`EnvironmentVariablesHolder`):**  用于管理构建过程中使用的环境变量。
4. **配置数据 (`ConfigurationDataHolder`):**  用于存储和操作构建配置数据，这些数据可以传递给源代码或其他构建步骤。
5. **依赖项 (`DependencyHolder`):**  用于表示项目依赖的外部库或内部模块。
6. **外部程序 (`ExternalProgramHolder`):**  用于表示构建过程中使用的外部可执行程序。
7. **外部库 (`ExternalLibraryHolder`):**  用于表示外部库文件。
8. **机器信息 (`MachineHolder`):**  用于表示构建或目标机器的体系结构信息。
9. **构建输出目录 (`IncludeDirsHolder`, `FileHolder`, `HeadersHolder`, `DataHolder`, `SymlinkDataHolder`, `InstallDirHolder`, `ManHolder`, `EmptyDirHolder`, `GeneratedObjectsHolder`):**  用于表示构建过程中产生的各种输出文件和目录。
10. **测试 (`Test`):** 用于定义和执行测试用例。

**与逆向方法的关系及举例说明:**

这个文件本身是 Meson 构建系统的一部分，主要用于构建 Frida 本身，而不是直接用于目标程序的逆向。然而，理解 Frida 的构建过程对于 Frida 的高级用户或开发者进行定制和问题排查是有帮助的。

* **理解 Frida 的依赖:** `DependencyHolder` 和 `ExternalProgramHolder` 揭示了 Frida 依赖的外部库和工具，例如 glib、v8 等。在逆向分析 Frida 本身时，了解这些依赖关系可以帮助理解 Frida 的架构和工作原理。
* **查看构建选项:** `FeatureOptionHolder` 允许用户在构建 Frida 时启用或禁用某些特性。这些特性可能直接影响 Frida 的功能和行为。例如，调试符号的包含与否会影响对 Frida 自身的逆向难度。
* **分析测试用例:** `Test` 类定义了 Frida 的测试用例。分析这些测试用例可以了解 Frida 的设计目标和预期行为，这对于理解 Frida 的功能很有帮助。

**与二进制底层、Linux、Android 内核及框架的知识关系及举例说明:**

虽然这个文件本身是 Python 代码，但它所操作的对象和执行的操作与底层的操作系统概念紧密相关：

* **进程执行 (`RunProcess`):**  直接涉及到操作系统进程的创建和管理。在 Linux 和 Android 上，这涉及到 `fork`, `execve` 等系统调用。Frida 在运行时会创建新的进程来加载目标应用或执行注入代码，理解进程执行机制对于理解 Frida 的工作方式至关重要。
* **环境变量 (`EnvironmentVariablesHolder`):** 环境变量是操作系统中用于配置进程行为的重要机制。Frida 可以通过环境变量来影响目标进程的加载和运行，例如设置 `LD_PRELOAD` 来劫持库函数。
* **外部程序 (`ExternalProgramHolder`):**  构建 Frida 的过程中可能需要调用如编译器 (gcc/clang)、链接器 (ld) 等底层工具。这些工具直接操作二进制代码。
* **机器信息 (`MachineHolder`):** 了解目标机器的架构 (例如 ARM, x86)、操作系统 (Linux, Android) 和内核版本对于正确构建和运行 Frida 非常重要。Frida 需要针对不同的架构进行编译。
* **依赖项 (`DependencyHolder`):** Frida 的某些依赖库可能直接与操作系统或内核交互，例如 glib 提供了很多底层系统调用的封装。

**逻辑推理的假设输入与输出:**

我们以 `FeatureOptionHolder` 的 `enabled_method` 为例：

**假设输入:**  一个 `FeatureOptionHolder` 对象，其内部持有的 `coredata.UserFeatureOption` 的 `value` 属性为 `'enabled'`。

**输出:** `True`

**逻辑推理:** `enabled_method` 的实现是检查 `self.value` 是否等于 `'enabled'`。由于假设输入中 `self.value` 为 `'enabled'`，因此方法返回 `True`。

再以 `RunProcess` 的 `run_command` 方法为例：

**假设输入:**
* `cmd`: 一个表示外部程序 `ls` 的 `ExternalProgram` 对象。
* `args`: `['-l', '/tmp']`
* `env`: 一个空的环境变量对象。
* `source_dir`, `build_dir`, `subdir`: 字符串，表示构建目录。
* `mesonintrospect`: 一个空列表。
* `in_builddir`: `False`
* `check`: `False`

**输出:**  一个元组 `(returncode, stdout, stderr)`。
* `returncode`:  外部命令 `ls -l /tmp` 的返回码 (通常为 0)。
* `stdout`:  命令 `ls -l /tmp` 的标准输出，列出 `/tmp` 目录的内容。
* `stderr`:  命令 `ls -l /tmp` 的标准错误输出 (通常为空)。

**逻辑推理:** `run_command` 方法会使用 `subprocess.Popen_safe` 执行给定的命令，并捕获其输出。基于 Linux 的行为，`ls -l /tmp` 会成功执行并输出目录内容到标准输出。

**涉及用户或编程常见的使用错误及举例说明:**

* **在配置对象使用后尝试修改 (`ConfigurationDataHolder`):**  用户在 `meson.build` 文件中定义了配置数据，并在某个目标中使用了该配置数据。之后，如果尝试再次修改该配置数据，会抛出 `InterpreterException`。这是因为 Meson 认为配置数据一旦被使用就不应该再被更改，以保证构建的一致性。

  ```python
  # meson.build
  conf_data = configuration_data()
  conf_data.set('my_option', 'initial_value')

  executable('my_program', 'my_program.c', configuration: conf_data)

  # 错误：在 executable 被定义后尝试修改 conf_data
  conf_data.set('my_option', 'new_value')
  ```

* **传递非绝对路径作为搜索目录 (`extract_search_dirs`):** 用户在 `find_library` 等函数中指定搜索目录时，如果传递了相对路径，会导致 `InvalidCode` 异常。Meson 强制使用绝对路径以避免歧义。

  ```python
  # meson.build
  find_library('mylib', dirs: ['relative/path']) # 错误
  find_library('mylib', dirs: ['/absolute/path']) # 正确
  ```

* **尝试获取未找到的外部程序的路径 (`ExternalProgramHolder`):**  如果用户尝试获取一个 Meson 无法找到的外部程序的路径，会抛出 `InterpreterException`。

  ```python
  # meson.build
  nonexistent_prog = find_program('nonexistent_program')
  if nonexistent_prog.found(): # 通常不会执行
      path = nonexistent_prog.path() # 如果执行到这里会报错
  ```

**用户操作是如何一步步的到达这里，作为调试线索:**

当用户执行 Meson 构建过程时，Meson 会解析 `meson.build` 文件。这个过程中，`interpreterobjects.py` 中定义的类会被实例化和使用：

1. **用户编写 `meson.build` 文件:**  用户在文件中使用 Meson 提供的函数，例如 `executable`, `find_library`, `configuration_data` 等。
2. **用户运行 `meson setup builddir`:** Meson 读取 `meson.build` 文件。
3. **Meson 解释器执行 `meson.build`:**  解释器会调用 `interpreterobjects.py` 中定义的类的构造函数来创建相应的对象，例如：
   * 当遇到 `configuration_data()` 时，会创建 `ConfigurationDataHolder` 的实例。
   * 当遇到 `find_program()` 时，会创建 `ExternalProgramHolder` 的实例。
   * 当遇到 `run_command()` 时 (如果 `meson.build` 中使用了自定义构建步骤)，会创建 `RunProcess` 的实例。
4. **Meson 存储构建信息:** 这些对象的状态和信息会被 Meson 存储起来，用于后续的构建和代码生成步骤。
5. **用户运行 `meson compile -C builddir`:**  在编译阶段，Meson 会根据之前存储的构建信息，调用编译器、链接器等工具。 `RunProcess` 对象会被用来执行自定义的命令。

**作为调试线索:**

* **构建失败:** 如果构建过程中出现错误，例如找不到依赖库或执行命令失败，错误信息可能会指向 `interpreterobjects.py` 中相关对象的处理逻辑。例如，如果 `find_library` 找不到库，可能是 `DependencyHolder` 的 `found_method` 返回了 `False`。
* **理解构建行为:**  如果用户想深入了解 Meson 如何处理特定的构建场景，例如如何查找库文件或如何执行自定义命令，可以查看 `interpreterobjects.py` 中相关类的实现。
* **Frida 自身构建问题:**  如果 Frida 的构建过程出现问题，开发者可能会需要查看这个文件来理解构建过程中涉及的对象和操作，从而定位问题。

**总结 `interpreterobjects.py` 的功能 (第 1 部分):**

`interpreterobjects.py` 文件在 Frida 的 Meson 构建系统中扮演着至关重要的角色，它定义了用于表示和操作各种构建相关实体的 Python 对象。这些对象涵盖了构建选项、进程执行、环境变量、配置数据、依赖项、外部程序和库、机器信息以及构建输出等多个方面。理解这些对象的功能对于理解 Frida 的构建过程、排查构建问题以及进行更高级的 Frida 开发和定制都非常有帮助。虽然这个文件本身不直接参与目标程序的逆向，但它构建了 Frida 这个逆向工具的基础。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/interpreterobjects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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