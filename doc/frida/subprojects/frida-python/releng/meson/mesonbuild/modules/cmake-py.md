Response:
Let's break down the thought process for analyzing the `cmake.py` file.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of this Python file within the context of the Frida dynamic instrumentation tool. We need to identify its purpose, how it interacts with other systems (like CMake), and how it might be relevant to reverse engineering and low-level system interaction. We also need to anticipate potential user errors and explain how a user might end up interacting with this code.

**2. Initial Skim and Keyword Identification:**

A quick skim of the code reveals keywords like "cmake", "subproject", "package", "version", "options", "target", "dependency", "include_directories", "configure", etc. These keywords immediately suggest the file's core purpose:  it's a Meson module that provides integration with CMake projects.

**3. Deeper Dive into Key Functions:**

Now, let's examine the main functions and classes:

* **`CmakeModule`:** This is the main module class. Its methods like `write_basic_package_version_file`, `configure_package_config_file`, and `subproject` are the entry points for users interacting with CMake projects through Meson.
* **`CMakeSubproject`:** This class represents a CMake subproject integrated into the Meson build. Its methods like `get_variable`, `dependency`, `target`, and `include_directories` allow access to information and components from the CMake subproject.
* **`CMakeSubprojectOptions`:**  This class handles configuration options for the CMake subproject, such as CMake defines, install settings, and compiler/linker arguments.

**4. Mapping Functionality to Concepts:**

Let's connect the identified functions and classes to their purpose:

* **`write_basic_package_version_file` and `configure_package_config_file`:** These clearly deal with creating CMake package configuration files, used for finding and using the built library in other CMake projects. This relates to packaging and distribution.
* **`subproject`:** This is the core function for integrating a CMake subproject. It allows Meson to orchestrate the build of an external CMake project.
* **Methods in `CMakeSubproject`:** These methods provide a way to access and utilize the outputs of the CMake subproject within the Meson build system. You can get variables, dependencies, include directories, and target information.
* **Methods in `CMakeSubprojectOptions`:** These functions allow users to customize the CMake build process for the subproject.

**5. Identifying Relevance to Reverse Engineering and Low-Level Concepts:**

Now, let's think about how this relates to the specific prompts:

* **Reverse Engineering:** The ability to integrate CMake projects opens doors for reverse engineering. Many libraries and tools used in reverse engineering might be built with CMake. Being able to incorporate these into a Frida build setup is valuable. The `dependency()` and `target()` methods are crucial here, allowing you to link against and use libraries built by CMake.
* **Binary/Low-Level, Linux/Android Kernel/Framework:**  CMake is often used to build libraries and tools that interact directly with the operating system, including kernel-level components or Android frameworks. If a Frida gadget or a tool used with Frida relies on such CMake-based components, this module is essential. The example of linking to a custom-built library using `cmake.subproject()` and then `libexample = cmake_proj.target('example')` demonstrates this.
* **Logic and Assumptions:** Look for conditional logic and assumptions made in the code. For example, the `detect_voidp_size` function assumes a C or C++ compiler is available. The package configuration file generation makes assumptions about standard installation directories.

**6. Considering User Errors and Usage Scenarios:**

Think about how a user might misuse this module:

* **Incorrect Arguments:**  Providing the wrong number or type of arguments to functions (e.g., `get_variable` requiring exactly one argument).
* **Non-existent Targets:** Trying to access a target in the CMake subproject that doesn't exist. The code explicitly handles this with an error message.
* **Conflicting Options:** Trying to use both `cmake_options` and `options` in the `subproject` function.
* **Missing CMake:**  Not having CMake installed or accessible in the PATH.

To understand the user's journey, trace back from the module's functionality. A user would likely start by wanting to incorporate a CMake project into their Frida build using `cmake.subproject()`. Then they might need to get dependencies using `cmake_proj.dependency()` or link to targets using `cmake_proj.target()`.

**7. Structuring the Answer:**

Finally, organize the information logically to address each part of the prompt. Start with a general overview of the module's function. Then, provide specific examples for reverse engineering, low-level concepts, logic/assumptions, and user errors. Conclude with an explanation of how a user might interact with this module.

**Self-Correction/Refinement:**

* **Initial thought:** "This is just about building CMake projects."
* **Correction:** "No, it's about *integrating* CMake projects into a Meson build, which is crucial for projects like Frida that might need to use external, CMake-based components."
* **Initial thought:** "Just list the functions."
* **Refinement:** "Explain the *purpose* of each key function and how they relate to the overall goal of CMake integration."
* **Initial thought:** "Focus only on the code."
* **Refinement:** "Think about the *user experience* and how someone would actually use this module, including potential pitfalls."

By following these steps, combining code analysis with conceptual understanding and user-centric thinking, we arrive at a comprehensive explanation of the `cmake.py` file's functionality and its relevance to the broader context of Frida.
这是 Frida 动态 instrumentation 工具中一个名为 `cmake.py` 的 Python 源代码文件，位于 `frida/subprojects/frida-python/releng/meson/mesonbuild/modules/` 目录下。 从其路径和文件名来看，它很明显是 [Meson](https://mesonbuild.com/) 构建系统的一个模块，专门用于处理与 [CMake](https://cmake.org/) 构建系统的集成。

**功能列举:**

这个 `cmake.py` 模块的主要功能是让 Meson 构建系统能够与 CMake 构建的项目进行交互。具体来说，它提供了以下功能：

1. **构建 CMake 子项目 (`subproject` 方法):**  允许将一个独立的 CMake 项目作为当前 Meson 项目的子项目进行构建。这使得 Frida 可以依赖使用 CMake 构建的外部库或组件。
2. **访问 CMake 子项目的信息 (`CMakeSubproject` 类及其方法):**
   - `get_variable`: 获取 CMake 子项目中定义的变量的值。
   - `dependency`:  将 CMake 子项目构建的库或目标作为 Meson 的依赖项。
   - `include_directories`: 获取 CMake 子项目提供的头文件目录，以便在 Meson 项目中使用。
   - `target`: 获取 CMake 子项目构建的目标（例如库或可执行文件）。
   - `target_type`: 获取 CMake 子项目构建的目标类型（例如 `library`, `executable`）。
   - `target_list`: 列出 CMake 子项目中的所有可用目标。
   - `found_method`: 检查 CMake 子项目是否成功找到。
3. **配置 CMake 子项目的构建选项 (`CMakeSubprojectOptions` 类及其方法):**
   - `add_cmake_defines`: 向 CMake 子项目传递预定义的宏。
   - `set_override_option`: 设置 CMake 子项目中特定选项的值。
   - `set_install`:  控制 CMake 子项目的安装行为。
   - `append_compile_args`: 向 CMake 子项目的编译命令添加额外的参数。
   - `append_link_args`: 向 CMake 子项目的链接命令添加额外的参数。
   - `clear`: 清除所有为 CMake 子项目设置的选项。
4. **生成 CMake 包配置文件 (`write_basic_package_version_file` 和 `configure_package_config_file` 方法):**
   - `write_basic_package_version_file`:  生成一个基本的 CMake 包版本文件，用于其他 CMake 项目查找和使用当前构建的库。
   - `configure_package_config_file`:  根据模板文件和配置数据生成更复杂的 CMake 包配置文件。
5. **检测 CMake 环境 (`detect_cmake` 方法):**  检查系统中是否安装了 CMake，并获取 CMake 的根目录。
6. **检测 `void*` 指针的大小 (`detect_voidp_size` 方法):**  用于生成包配置文件时确定目标平台的指针大小。

**与逆向方法的关系及举例:**

这个模块与逆向工程密切相关，因为逆向工程经常需要使用各种工具和库，其中许多是使用 CMake 构建的。 Frida 作为一个动态 instrumentation 框架，可能需要依赖或集成一些用 CMake 构建的组件。

**举例:**

假设 Frida 需要集成一个用 CMake 构建的自定义代码注入库 `InjectionLib`。这个 `cmake.py` 模块可以这样使用：

```python
# meson.build (Frida 的构建文件)

cmake_proj = import('cmake').subproject('InjectionLib')  # 假设 InjectionLib 目录与 Frida 的 meson.build 在同一层级

if cmake_proj.found():
    injection_lib = cmake_proj.target('InjectionLib')  # 假设 CMake 项目中定义了一个名为 InjectionLib 的库目标

    frida_module = shared_module('my_frida_module',
        'my_frida_module.c',
        link_with : injection_lib, # 将 InjectionLib 链接到 Frida 模块
        dependencies : [
            dependency('glib-2.0'),
            # ...其他 Frida 依赖
        ]
    )
else:
    message('InjectionLib not found, skipping module build.')
```

在这个例子中：

- `import('cmake').subproject('InjectionLib')`  使用 `cmake.py` 模块将 `InjectionLib` CMake 项目作为子项目构建。
- `cmake_proj.target('InjectionLib')`  获取 `InjectionLib` CMake 项目构建的库目标。
- `link_with : injection_lib`  将这个库链接到 Frida 的一个本地模块 `my_frida_module`。

这样，Frida 就可以利用 `InjectionLib` 提供的代码注入功能，这对于动态分析和逆向工程至关重要。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例:**

CMake 经常用于构建与操作系统底层交互的库和工具，包括与 Linux 内核或 Android 框架相关的组件。通过 `cmake.py` 模块集成这些项目，Frida 可以利用这些底层能力。

**举例:**

假设一个用于监控 Android 系统调用的库 `SyscallMonitor` 是用 CMake 构建的。

```python
# meson.build

cmake_syscall_monitor = import('cmake').subproject('SyscallMonitor')

if cmake_syscall_monitor.found():
    syscall_monitor_lib = cmake_syscall_monitor.target('syscall_monitor')
    syscall_monitor_include = cmake_syscall_monitor.include_directories()

    frida_gadget = shared_library('frida-gadget',
        'frida-gadget.c',
        link_with : syscall_monitor_lib,
        include_directories : syscall_monitor_include,
        # ... 其他 Gadget 配置
    )
```

在这个例子中，Frida 的 Gadget 可以链接到 `SyscallMonitor` 库，并使用其提供的接口来监控 Android 系统的底层活动，这直接涉及到 Android 内核和框架的知识。

**逻辑推理及假设输入与输出:**

假设我们调用 `cmake_proj.target_type('MyLibrary')`，其中 `MyLibrary` 是 `InjectionLib` CMake 子项目中的一个目标。

**假设输入:**

- `cmake_proj`:  一个 `CMakeSubproject` 类的实例，代表已成功构建的 `InjectionLib` CMake 子项目。
- `'MyLibrary'`:  一个字符串，表示要查询的目标名称。

**逻辑推理:**

`target_type` 方法会调用 `self.cm_interpreter.target_info(tgt)` 来获取目标信息，其中 `self.cm_interpreter` 是用于与 CMake 子项目交互的解释器。 这个解释器会解析 CMake 的构建结果，确定目标 `MyLibrary` 的类型。

**可能输出:**

- 如果 `MyLibrary` 是一个静态库，则输出可能是字符串 `"library"`。
- 如果 `MyLibrary` 是一个共享库，则输出可能是字符串 `"shared_library"`。
- 如果 `MyLibrary` 是一个可执行文件，则输出可能是字符串 `"executable"`。
- 如果 `MyLibrary` 不存在，则会抛出一个 `InterpreterException`。

**涉及用户或编程常见的使用错误及举例:**

1. **目标名称错误:** 用户在调用 `cmake_proj.target('IncorectLibName')` 时，如果 CMake 子项目中不存在名为 `IncorectLibName` 的目标，会导致错误。

   **错误示例:**  `meson.build:10:0: ERROR: The CMake target IncorectLibName does not exist`

2. **传递错误的参数类型:**  例如，`cmake_proj.get_variable(123)`，`get_variable` 期望接收字符串类型的变量名，但用户传递了一个整数。

   **错误示例:**  `meson.build:15:0: ERROR: Exactly one argument is required.`

3. **在 `subproject` 中同时使用 `options` 和 `cmake_options`:** 这是不允许的，因为它们的功能有重叠。

   **错误示例:** `meson.build:5:0: ERROR: "options" cannot be used together with "cmake_options"`

4. **依赖不存在的 CMake 子项目:**  如果 `import('cmake').subproject('NonExistentProject')` 中的 `'NonExistentProject'` 目录不存在或不是一个有效的 CMake 项目，构建会失败。

   **错误示例:** (取决于 Meson 的错误报告，可能指示找不到子项目)。

**用户操作是如何一步步到达这里的 (调试线索):**

当用户在编写 Frida 的构建脚本 `meson.build` 文件时，想要集成一个使用 CMake 构建的外部库或组件，他们会按照以下步骤操作，最终会涉及到 `cmake.py` 模块：

1. **确定需要集成 CMake 项目:**  用户发现某个功能需要依赖一个 CMake 构建的库。
2. **在 `meson.build` 中使用 `import('cmake')`:** 用户需要在 `meson.build` 文件中导入 `cmake` 模块，以便使用其提供的功能。
3. **调用 `cmake.subproject()`:** 用户使用 `cmake.subproject('path/to/cmake/project')` 来声明一个 CMake 子项目。Meson 会解析这个调用，并加载 `cmake.py` 模块。
4. **配置 CMake 子项目 (可选):** 用户可能使用 `cmake_proj_options = import('cmake').subproject_options()` 创建一个 `CMakeSubprojectOptions` 对象，并使用其方法（如 `add_cmake_defines`, `set_override_option`）来配置 CMake 子项目的构建选项。这些操作会调用 `cmake.py` 中 `CMakeSubprojectOptions` 类的方法。
5. **访问 CMake 子项目的输出:** 用户通过 `cmake_proj.target('target_name')`, `cmake_proj.dependency('dependency_name')`, `cmake_proj.include_directories()` 等方法来获取 CMake 子项目构建的库、依赖和头文件目录。 这些方法会调用 `cmake.py` 中 `CMakeSubproject` 类的方法，进而与实际的 CMake 构建过程交互。
6. **构建 Meson 项目:** 当用户运行 `meson setup builddir` 和 `ninja -C builddir` 等命令时，Meson 会执行 `cmake.py` 模块中的代码，驱动 CMake 子项目的构建，并将结果集成到整个 Frida 的构建过程中。

如果在这些步骤中出现错误，例如指定了不存在的 CMake 目标，Meson 的错误消息可能会指向 `meson.build` 文件中调用 `cmake_proj.target()` 的位置。为了调试这类问题，开发者可能需要查看 `cmake.py` 的源代码，理解其内部逻辑，以及 Meson 如何与 CMake 进行交互。例如，他们可能会查看 `CMakeSubproject` 的 `target` 方法，了解它是如何查找和返回 CMake 构建目标的。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/modules/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2018 The Meson development team

from __future__ import annotations
import re
import os, os.path, pathlib
import shutil
import typing as T

from . import ExtensionModule, ModuleReturnValue, ModuleObject, ModuleInfo

from .. import build, mesonlib, mlog, dependencies
from ..cmake import TargetOptions, cmake_defines_to_args
from ..interpreter import SubprojectHolder
from ..interpreter.type_checking import NATIVE_KW, REQUIRED_KW, INSTALL_DIR_KW, NoneType, in_set_validator
from ..interpreterbase import (
    FeatureNew,
    FeatureNewKwargs,

    stringArgs,
    permittedKwargs,
    noPosargs,
    noKwargs,

    InvalidArguments,
    InterpreterException,

    typed_pos_args,
    typed_kwargs,
    KwargInfo,
    ContainerTypeInfo,
)

if T.TYPE_CHECKING:
    from typing_extensions import TypedDict

    from . import ModuleState
    from ..cmake import SingleTargetOptions
    from ..environment import Environment
    from ..interpreter import Interpreter, kwargs
    from ..interpreterbase import TYPE_kwargs, TYPE_var

    class WriteBasicPackageVersionFile(TypedDict):

        arch_independent: bool
        compatibility: str
        install_dir: T.Optional[str]
        name: str
        version: str

    class ConfigurePackageConfigFile(TypedDict):

        configuration: T.Union[build.ConfigurationData, dict]
        input: T.Union[str, mesonlib.File]
        install_dir: T.Optional[str]
        name: str

    class Subproject(kwargs.ExtractRequired):

        options: T.Optional[CMakeSubprojectOptions]
        cmake_options: T.List[str]
        native: mesonlib.MachineChoice


COMPATIBILITIES = ['AnyNewerVersion', 'SameMajorVersion', 'SameMinorVersion', 'ExactVersion']

# Taken from https://github.com/Kitware/CMake/blob/master/Modules/CMakePackageConfigHelpers.cmake
PACKAGE_INIT_BASE = '''
####### Expanded from \\@PACKAGE_INIT\\@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was @inputFileName@ ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/@PACKAGE_RELATIVE_PATH@" ABSOLUTE)
'''
PACKAGE_INIT_EXT = '''
# Use original install prefix when loaded through a "/usr move"
# cross-prefix symbolic link such as /lib -> /usr/lib.
get_filename_component(_realCurr "${CMAKE_CURRENT_LIST_DIR}" REALPATH)
get_filename_component(_realOrig "@absInstallDir@" REALPATH)
if(_realCurr STREQUAL _realOrig)
  set(PACKAGE_PREFIX_DIR "@installPrefix@")
endif()
unset(_realOrig)
unset(_realCurr)
'''
PACKAGE_INIT_SET_AND_CHECK = '''
macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

####################################################################################
'''

class CMakeSubproject(ModuleObject):
    def __init__(self, subp: SubprojectHolder):
        assert isinstance(subp, SubprojectHolder)
        assert subp.cm_interpreter is not None
        super().__init__()
        self.subp = subp
        self.cm_interpreter = subp.cm_interpreter
        self.methods.update({'get_variable': self.get_variable,
                             'dependency': self.dependency,
                             'include_directories': self.include_directories,
                             'target': self.target,
                             'target_type': self.target_type,
                             'target_list': self.target_list,
                             'found': self.found_method,
                             })

    def _args_to_info(self, args: T.List[str]) -> T.Dict[str, str]:
        if len(args) != 1:
            raise InterpreterException('Exactly one argument is required.')

        tgt = args[0]
        res = self.cm_interpreter.target_info(tgt)
        if res is None:
            raise InterpreterException(f'The CMake target {tgt} does not exist\n' +
                                       '  Use the following command in your meson.build to list all available targets:\n\n' +
                                       '    message(\'CMake targets:\\n - \' + \'\\n - \'.join(<cmake_subproject>.target_list()))')

        # Make sure that all keys are present (if not this is a bug)
        assert all(x in res for x in ['inc', 'src', 'dep', 'tgt', 'func'])
        return res

    @noKwargs
    @stringArgs
    def get_variable(self, state: ModuleState, args: T.List[str], kwargs: TYPE_kwargs) -> TYPE_var:
        return self.subp.get_variable_method(args, kwargs)

    @FeatureNewKwargs('dependency', '0.56.0', ['include_type'])
    @permittedKwargs({'include_type'})
    @stringArgs
    def dependency(self, state: ModuleState, args: T.List[str], kwargs: T.Dict[str, str]) -> dependencies.Dependency:
        info = self._args_to_info(args)
        if info['func'] == 'executable':
            raise InvalidArguments(f'{args[0]} is an executable and does not support the dependency() method. Use target() instead.')
        orig = self.get_variable(state, [info['dep']], {})
        assert isinstance(orig, dependencies.Dependency)
        actual = orig.include_type
        if 'include_type' in kwargs and kwargs['include_type'] != actual:
            mlog.debug('Current include type is {}. Converting to requested {}'.format(actual, kwargs['include_type']))
            return orig.generate_system_dependency(kwargs['include_type'])
        return orig

    @noKwargs
    @stringArgs
    def include_directories(self, state: ModuleState, args: T.List[str], kwargs: TYPE_kwargs) -> build.IncludeDirs:
        info = self._args_to_info(args)
        return self.get_variable(state, [info['inc']], kwargs)

    @noKwargs
    @stringArgs
    def target(self, state: ModuleState, args: T.List[str], kwargs: TYPE_kwargs) -> build.Target:
        info = self._args_to_info(args)
        return self.get_variable(state, [info['tgt']], kwargs)

    @noKwargs
    @stringArgs
    def target_type(self, state: ModuleState, args: T.List[str], kwargs: TYPE_kwargs) -> str:
        info = self._args_to_info(args)
        return info['func']

    @noPosargs
    @noKwargs
    def target_list(self, state: ModuleState, args: TYPE_var, kwargs: TYPE_kwargs) -> T.List[str]:
        return self.cm_interpreter.target_list()

    @noPosargs
    @noKwargs
    @FeatureNew('CMakeSubproject.found()', '0.53.2')
    def found_method(self, state: ModuleState, args: TYPE_var, kwargs: TYPE_kwargs) -> bool:
        return self.subp is not None


class CMakeSubprojectOptions(ModuleObject):
    def __init__(self) -> None:
        super().__init__()
        self.cmake_options: T.List[str] = []
        self.target_options = TargetOptions()

        self.methods.update(
            {
                'add_cmake_defines': self.add_cmake_defines,
                'set_override_option': self.set_override_option,
                'set_install': self.set_install,
                'append_compile_args': self.append_compile_args,
                'append_link_args': self.append_link_args,
                'clear': self.clear,
            }
        )

    def _get_opts(self, kwargs: dict) -> SingleTargetOptions:
        if 'target' in kwargs:
            return self.target_options[kwargs['target']]
        return self.target_options.global_options

    @typed_pos_args('subproject_options.add_cmake_defines', varargs=dict)
    @noKwargs
    def add_cmake_defines(self, state: ModuleState, args: T.Tuple[T.List[T.Dict[str, TYPE_var]]], kwargs: TYPE_kwargs) -> None:
        self.cmake_options += cmake_defines_to_args(args[0])

    @typed_pos_args('subproject_options.set_override_option', str, str)
    @permittedKwargs({'target'})
    def set_override_option(self, state: ModuleState, args: T.Tuple[str, str], kwargs: TYPE_kwargs) -> None:
        self._get_opts(kwargs).set_opt(args[0], args[1])

    @typed_pos_args('subproject_options.set_install', bool)
    @permittedKwargs({'target'})
    def set_install(self, state: ModuleState, args: T.Tuple[bool], kwargs: TYPE_kwargs) -> None:
        self._get_opts(kwargs).set_install(args[0])

    @typed_pos_args('subproject_options.append_compile_args', str, varargs=str, min_varargs=1)
    @permittedKwargs({'target'})
    def append_compile_args(self, state: ModuleState, args: T.Tuple[str, T.List[str]], kwargs: TYPE_kwargs) -> None:
        self._get_opts(kwargs).append_args(args[0], args[1])

    @typed_pos_args('subproject_options.append_link_args', varargs=str, min_varargs=1)
    @permittedKwargs({'target'})
    def append_link_args(self, state: ModuleState, args: T.Tuple[T.List[str]], kwargs: TYPE_kwargs) -> None:
        self._get_opts(kwargs).append_link_args(args[0])

    @noPosargs
    @noKwargs
    def clear(self, state: ModuleState, args: TYPE_var, kwargs: TYPE_kwargs) -> None:
        self.cmake_options.clear()
        self.target_options = TargetOptions()


class CmakeModule(ExtensionModule):
    cmake_detected = False
    cmake_root = None

    INFO = ModuleInfo('cmake', '0.50.0')

    def __init__(self, interpreter: Interpreter) -> None:
        super().__init__(interpreter)
        self.methods.update({
            'write_basic_package_version_file': self.write_basic_package_version_file,
            'configure_package_config_file': self.configure_package_config_file,
            'subproject': self.subproject,
            'subproject_options': self.subproject_options,
        })

    def detect_voidp_size(self, env: Environment) -> int:
        compilers = env.coredata.compilers.host
        compiler = compilers.get('c', None)
        if not compiler:
            compiler = compilers.get('cpp', None)

        if not compiler:
            raise mesonlib.MesonException('Requires a C or C++ compiler to compute sizeof(void *).')

        return compiler.sizeof('void *', '', env)[0]

    def detect_cmake(self, state: ModuleState) -> bool:
        if self.cmake_detected:
            return True

        cmakebin = state.find_program('cmake', silent=False)
        if not cmakebin.found():
            return False

        p, stdout, stderr = mesonlib.Popen_safe(cmakebin.get_command() + ['--system-information', '-G', 'Ninja'])[0:3]
        if p.returncode != 0:
            mlog.log(f'error retrieving cmake information: returnCode={p.returncode} stdout={stdout} stderr={stderr}')
            return False

        match = re.search('\nCMAKE_ROOT \\"([^"]+)"\n', stdout.strip())
        if not match:
            mlog.log('unable to determine cmake root')
            return False

        cmakePath = pathlib.PurePath(match.group(1))
        self.cmake_root = os.path.join(*cmakePath.parts)
        self.cmake_detected = True
        return True

    @noPosargs
    @typed_kwargs(
        'cmake.write_basic_package_version_file',
        KwargInfo('arch_independent', bool, default=False, since='0.62.0'),
        KwargInfo('compatibility', str, default='AnyNewerVersion', validator=in_set_validator(set(COMPATIBILITIES))),
        KwargInfo('name', str, required=True),
        KwargInfo('version', str, required=True),
        INSTALL_DIR_KW,
    )
    def write_basic_package_version_file(self, state: ModuleState, args: TYPE_var, kwargs: 'WriteBasicPackageVersionFile') -> ModuleReturnValue:
        arch_independent = kwargs['arch_independent']
        compatibility = kwargs['compatibility']
        name = kwargs['name']
        version = kwargs['version']

        if not self.detect_cmake(state):
            raise mesonlib.MesonException('Unable to find cmake')

        pkgroot = pkgroot_name = kwargs['install_dir']
        if pkgroot is None:
            pkgroot = os.path.join(state.environment.coredata.get_option(mesonlib.OptionKey('libdir')), 'cmake', name)
            pkgroot_name = os.path.join('{libdir}', 'cmake', name)

        template_file = os.path.join(self.cmake_root, 'Modules', f'BasicConfigVersion-{compatibility}.cmake.in')
        if not os.path.exists(template_file):
            raise mesonlib.MesonException(f'your cmake installation doesn\'t support the {compatibility} compatibility')

        version_file = os.path.join(state.environment.scratch_dir, f'{name}ConfigVersion.cmake')

        conf: T.Dict[str, T.Union[str, bool, int]] = {
            'CVF_VERSION': version,
            'CMAKE_SIZEOF_VOID_P': str(self.detect_voidp_size(state.environment)),
            'CVF_ARCH_INDEPENDENT': arch_independent,
        }
        mesonlib.do_conf_file(template_file, version_file, build.ConfigurationData(conf), 'meson')

        res = build.Data([mesonlib.File(True, state.environment.get_scratch_dir(), version_file)], pkgroot, pkgroot_name, None, state.subproject)
        return ModuleReturnValue(res, [res])

    def create_package_file(self, infile: str, outfile: str, PACKAGE_RELATIVE_PATH: str, extra: str, confdata: build.ConfigurationData) -> None:
        package_init = PACKAGE_INIT_BASE.replace('@PACKAGE_RELATIVE_PATH@', PACKAGE_RELATIVE_PATH)
        package_init = package_init.replace('@inputFileName@', os.path.basename(infile))
        package_init += extra
        package_init += PACKAGE_INIT_SET_AND_CHECK

        try:
            with open(infile, encoding='utf-8') as fin:
                data = fin.readlines()
        except Exception as e:
            raise mesonlib.MesonException(f'Could not read input file {infile}: {e!s}')

        result = []
        regex = mesonlib.get_variable_regex('cmake@')
        for line in data:
            line = line.replace('@PACKAGE_INIT@', package_init)
            line, _missing = mesonlib.do_replacement(regex, line, 'cmake@', confdata)

            result.append(line)

        outfile_tmp = outfile + "~"
        with open(outfile_tmp, "w", encoding='utf-8') as fout:
            fout.writelines(result)

        shutil.copymode(infile, outfile_tmp)
        mesonlib.replace_if_different(outfile, outfile_tmp)

    @noPosargs
    @typed_kwargs(
        'cmake.configure_package_config_file',
        KwargInfo('configuration', (build.ConfigurationData, dict), required=True),
        KwargInfo('input',
                  (str, mesonlib.File, ContainerTypeInfo(list, mesonlib.File)), required=True,
                  validator=lambda x: 'requires exactly one file' if isinstance(x, list) and len(x) != 1 else None,
                  convertor=lambda x: x[0] if isinstance(x, list) else x),
        KwargInfo('name', str, required=True),
        INSTALL_DIR_KW,
    )
    def configure_package_config_file(self, state: ModuleState, args: TYPE_var, kwargs: 'ConfigurePackageConfigFile') -> build.Data:
        inputfile = kwargs['input']
        if isinstance(inputfile, str):
            inputfile = mesonlib.File.from_source_file(state.environment.source_dir, state.subdir, inputfile)

        ifile_abs = inputfile.absolute_path(state.environment.source_dir, state.environment.build_dir)

        name = kwargs['name']

        (ofile_path, ofile_fname) = os.path.split(os.path.join(state.subdir, f'{name}Config.cmake'))
        ofile_abs = os.path.join(state.environment.build_dir, ofile_path, ofile_fname)

        install_dir = kwargs['install_dir']
        if install_dir is None:
            install_dir = os.path.join(state.environment.coredata.get_option(mesonlib.OptionKey('libdir')), 'cmake', name)

        conf = kwargs['configuration']
        if isinstance(conf, dict):
            FeatureNew.single_use('cmake.configure_package_config_file dict as configuration', '0.62.0', state.subproject, location=state.current_node)
            conf = build.ConfigurationData(conf)

        prefix = state.environment.coredata.get_option(mesonlib.OptionKey('prefix'))
        abs_install_dir = install_dir
        if not os.path.isabs(abs_install_dir):
            abs_install_dir = os.path.join(prefix, install_dir)

        # path used in cmake scripts are POSIX even on Windows
        PACKAGE_RELATIVE_PATH = pathlib.PurePath(os.path.relpath(prefix, abs_install_dir)).as_posix()
        extra = ''
        if re.match('^(/usr)?/lib(64)?/.+', abs_install_dir):
            extra = PACKAGE_INIT_EXT.replace('@absInstallDir@', abs_install_dir)
            extra = extra.replace('@installPrefix@', prefix)

        self.create_package_file(ifile_abs, ofile_abs, PACKAGE_RELATIVE_PATH, extra, conf)
        conf.used = True

        conffile = os.path.normpath(inputfile.relative_name())
        self.interpreter.build_def_files.add(conffile)

        res = build.Data([mesonlib.File(True, ofile_path, ofile_fname)], install_dir, install_dir, None, state.subproject)
        self.interpreter.build.data.append(res)

        return res

    @FeatureNew('subproject', '0.51.0')
    @typed_pos_args('cmake.subproject', str)
    @typed_kwargs(
        'cmake.subproject',
        REQUIRED_KW,
        NATIVE_KW.evolve(since='1.3.0'),
        KwargInfo('options', (CMakeSubprojectOptions, NoneType), since='0.55.0'),
        KwargInfo(
            'cmake_options',
            ContainerTypeInfo(list, str),
            default=[],
            listify=True,
            deprecated='0.55.0',
            deprecated_message='Use options instead',
        ),
    )
    def subproject(self, state: ModuleState, args: T.Tuple[str], kwargs_: Subproject) -> T.Union[SubprojectHolder, CMakeSubproject]:
        if kwargs_['cmake_options'] and kwargs_['options'] is not None:
            raise InterpreterException('"options" cannot be used together with "cmake_options"')
        dirname = args[0]
        kw: kwargs.DoSubproject = {
            'required': kwargs_['required'],
            'options': kwargs_['options'],
            'cmake_options': kwargs_['cmake_options'],
            'default_options': {},
            'version': [],
            'for_machine': kwargs_['native'],
        }
        subp = self.interpreter.do_subproject(dirname, kw, force_method='cmake')
        if not subp.found():
            return subp
        return CMakeSubproject(subp)

    @FeatureNew('subproject_options', '0.55.0')
    @noKwargs
    @noPosargs
    def subproject_options(self, state: ModuleState, args: TYPE_var, kwargs: TYPE_kwargs) -> CMakeSubprojectOptions:
        return CMakeSubprojectOptions()

def initialize(*args: T.Any, **kwargs: T.Any) -> CmakeModule:
    return CmakeModule(*args, **kwargs)
```