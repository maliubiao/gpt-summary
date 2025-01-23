Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Goal:** The primary goal is to understand the functionality of the `cmake.py` file within the Frida project. Specifically, we need to identify its purpose, how it relates to reverse engineering, its use of low-level concepts, any logic or assumptions, potential user errors, and how a user might interact with this code.

2. **High-Level Overview:**  The first thing to notice is the module name: `cmake`. This strongly suggests that the module is designed to interact with CMake, a popular cross-platform build system. The file path (`frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/cmake.py`) reinforces this, as it's part of Meson's build system for Frida. This immediately tells us this code is about integrating CMake-based projects into a Meson build.

3. **Core Functionality Identification:**  Scan the class and function definitions for keywords and purpose. Look for verbs like `write`, `configure`, `subproject`, `get`, `set`, `append`, etc.

    * **`write_basic_package_version_file` and `configure_package_config_file`:**  These methods strongly suggest they are involved in creating CMake package configuration files. These files are crucial for CMake's `find_package` mechanism, allowing projects to locate and link against external libraries.

    * **`CMakeSubproject` class and `subproject` method:** The name `Subproject` and the method `subproject` clearly indicate this is about including CMake-based subprojects within the Meson build.

    * **`CMakeSubprojectOptions` class and `subproject_options` method:** This class likely deals with configuring options specific to the CMake subproject. Methods like `add_cmake_defines`, `set_override_option`, `append_compile_args`, and `append_link_args` confirm this by exposing common CMake configuration elements.

    * **Methods within `CMakeSubproject` (e.g., `get_variable`, `dependency`, `include_directories`, `target`):** These methods suggest a way to access information and dependencies from the integrated CMake subproject within the Meson build environment.

4. **Relating to Reverse Engineering:** Think about how CMake and external libraries/projects are used in reverse engineering.

    * **Dependency Management:** Reverse engineering tools often rely on libraries for parsing, disassembling, or analyzing binaries. CMake is commonly used to build these libraries. This module helps integrate such libraries into the Frida build process.

    * **Frida's Architecture:** Frida itself is a dynamic instrumentation framework. It likely needs to build components that interact with target processes. These components might be built using CMake.

5. **Identifying Low-Level Concepts:** Look for interactions with operating system features, compilers, and binary formats.

    * **Compiler Interaction:** The `detect_voidp_size` function directly interacts with the compiler to determine the size of a pointer. This is a low-level detail crucial for ABI compatibility.

    * **File System Operations:**  The module manipulates files and directories (`os.path`, `shutil`), demonstrating interaction with the underlying operating system.

    * **Process Execution:**  `mesonlib.Popen_safe` is used to execute CMake, indicating interaction with external processes.

6. **Analyzing Logic and Assumptions:** Look for conditional statements, loops, and data transformations.

    * **Package File Generation Logic:** The code for generating package configuration files involves string manipulation, template replacement, and conditional inclusion of extra content based on install directories.

    * **Subproject Handling:** The `subproject` method orchestrates the inclusion of a CMake project, making assumptions about the project's structure and build process.

7. **Identifying Potential User Errors:** Consider common mistakes developers make when integrating external build systems.

    * **Incorrect Paths/Names:** Specifying the wrong directory for the CMake subproject or incorrect target names within the subproject.
    * **Option Conflicts:** Trying to use both `cmake_options` and `options` simultaneously.
    * **Missing CMake:** Not having CMake installed or accessible in the environment.
    * **Incompatible CMake Versions:** Using features that are not supported by the installed CMake version.

8. **Tracing User Interaction:** Think about the typical workflow of a Frida developer using Meson.

    * They would edit `meson.build` files.
    * They would use the `cmake.subproject()` function to integrate a CMake project.
    * They might use `cmake.subproject_options()` to configure the CMake project.
    * They would run `meson` and `ninja` (or another backend) to build the project. The `cmake.py` module would be invoked during the Meson configuration phase.

9. **Structuring the Answer:** Organize the findings into logical categories as requested by the prompt: functionality, relation to reverse engineering, low-level aspects, logic/assumptions, user errors, and user interaction. Provide specific code snippets as examples where possible.

10. **Refinement and Review:**  Read through the analysis and ensure clarity, accuracy, and completeness. Double-check the code for any missed details or misinterpretations. For example, initially, I might have focused too much on the `CMakeSubproject` class's internal methods and not enough on the broader context of integrating CMake projects. Review helps catch these imbalances.
这是一个名为 `cmake.py` 的 Python 模块，位于 Frida 动态 instrumentation 工具的源代码目录 `frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/` 下。它的作用是为 Meson 构建系统提供与 CMake 构建系统集成的功能。简单来说，它允许你在使用 Meson 构建 Frida 的时候，方便地包含和使用基于 CMake 的子项目或依赖项。

下面详细列举其功能，并根据你的要求进行说明：

**功能列表:**

1. **写入基本的包版本文件 (`write_basic_package_version_file`):**
   - 功能：生成一个基本的 CMake 包版本文件 (`<name>ConfigVersion.cmake`)。这个文件用于 CMake 的 `find_package` 命令来确定包的版本兼容性。
   - 涉及 CMake 知识：直接操作 CMake 的包管理机制，生成符合 CMake 规范的版本文件。
   - 逻辑推理：假设输入包的名称、版本和兼容性要求，输出一个包含这些信息的 CMake 版本文件。例如，如果输入 `name='mylib'`, `version='1.2.3'`, `compatibility='SameMajorVersion'`，则生成的版本文件将允许 `find_package(mylib)` 找到 1.x.y 版本的库。

2. **配置包配置文件 (`configure_package_config_file`):**
   - 功能：处理一个 CMake 包配置文件的模板 (`<name>Config.cmake.in`)，并根据提供的配置数据生成最终的配置文件 (`<name>Config.cmake`)。这通常用于定义库的编译选项、链接库、包含路径等信息。
   - 涉及 CMake 知识：利用 CMake 的变量替换机制 (`@variable@`)，将 Meson 的配置数据注入到 CMake 配置文件中。
   - 逻辑推理：假设输入一个包含 CMake 变量的模板文件和一个配置字典，输出一个替换了变量的 CMake 配置文件。例如，模板文件中有 `@MY_LIB_INCLUDE_DIR@`，配置字典中有 `{'MY_LIB_INCLUDE_DIR': '/path/to/include'}`，则生成的配置文件中该变量会被替换为 `/path/to/include`。
   - 用户或编程常见的使用错误：
     - 模板文件中使用的变量名与配置字典中的键不匹配。
     - 提供的输入文件路径错误。
     - 忘记在 `meson.build` 中声明依赖。

3. **添加 CMake 子项目 (`subproject`):**
   - 功能：将一个基于 CMake 的项目作为子项目集成到当前的 Meson 构建中。这允许你在 Meson 项目中依赖 CMake 项目的构建产物。
   - 涉及 CMake, Linux, Android 内核及框架知识：
     - **CMake:**  直接调用 CMake 来构建子项目，需要了解 CMake 的构建流程和选项。
     - **Linux/Android:** CMake 子项目可能涉及特定平台的编译选项、链接库等，这可能与 Linux 或 Android 系统的库和框架有关。例如，CMake 子项目可能需要链接 `pthread` 库（Linux）或 Android NDK 中的库。
   - 逻辑推理：假设指定一个包含 `CMakeLists.txt` 的目录，Meson 会调用 CMake 构建该目录下的项目，并允许访问其构建产物（如库、头文件）。
   - 用户或编程常见的使用错误：
     - 指定的子项目目录不存在或不包含有效的 `CMakeLists.txt` 文件。
     - CMake 子项目的构建失败（例如，缺少依赖）。
     - 在 Meson 中错误地引用 CMake 子项目的目标。

4. **配置 CMake 子项目选项 (`subproject_options`):**
   - 功能：提供一个对象，用于配置 CMake 子项目的构建选项，例如添加 CMake 定义、设置覆盖选项、设置安装行为、追加编译和链接参数等。
   - 涉及 CMake 知识：允许用户通过 Meson API 传递 CMake 特定的选项，例如 `-D<variable>=<value>`。
   - 逻辑推理：用户可以通过 `subproject_options` 对象设置各种 CMake 选项，这些选项会在调用 CMake 构建子项目时生效。

5. **获取 CMake 子项目的变量 (`CMakeSubproject.get_variable`):**
   - 功能：从已集成的 CMake 子项目中获取指定的变量值。
   - 涉及 CMake 知识：需要知道 CMake 子项目中定义的变量名。
   - 逻辑推理：假设 CMake 子项目中定义了变量 `MY_VAR`，可以使用 `cmake_subproject.get_variable('MY_VAR')` 获取其值。
   - 用户或编程常见的使用错误：请求不存在的 CMake 变量。

6. **获取 CMake 子项目的依赖 (`CMakeSubproject.dependency`):**
   - 功能：将 CMake 子项目构建出的库或其他依赖项作为 Meson 的依赖项引入。
   - 涉及 CMake, Linux, Android 内核及框架知识：
     - **CMake:** 理解 CMake 如何定义库目标。
     - **Linux/Android:** CMake 子项目构建的库可能是系统库或框架的一部分，例如 Android 的 `liblog.so`。
   - 逻辑推理：假设 CMake 子项目构建了一个名为 `mylib` 的共享库，可以使用 `cmake_subproject.dependency('mylib')` 在 Meson 中声明对其的依赖。

7. **获取 CMake 子项目的包含目录 (`CMakeSubproject.include_directories`):**
   - 功能：获取 CMake 子项目目标对外暴露的包含目录。
   - 涉及 CMake 知识：理解 CMake 如何定义目标的包含目录。
   - 逻辑推理：假设 CMake 子项目的目标 `mytarget` 定义了包含目录 `/path/to/headers`，可以使用 `cmake_subproject.include_directories('mytarget')` 在 Meson 中使用这些包含目录。

8. **获取 CMake 子项目的目标 (`CMakeSubproject.target`):**
   - 功能：获取 CMake 子项目构建出的目标（如库、可执行文件）。
   - 涉及 CMake 知识：理解 CMake 中目标的定义。
   - 逻辑推理：假设 CMake 子项目构建了一个名为 `myexe` 的可执行文件，可以使用 `cmake_subproject.target('myexe')` 在 Meson 中引用它。

9. **获取 CMake 子项目的目标类型 (`CMakeSubproject.target_type`):**
   - 功能：获取 CMake 子项目目标的类型（例如，`executable`, `shared_library`, `static_library`）。
   - 涉及 CMake 知识：理解 CMake 中不同目标类型的定义。

10. **列出 CMake 子项目的目标 (`CMakeSubproject.target_list`):**
    - 功能：列出 CMake 子项目中定义的所有目标。
    - 涉及 CMake 知识：需要理解 CMake 中目标的定义和管理。
    - 逻辑推理：调用此方法会返回一个字符串列表，其中包含 CMake 子项目 `CMakeLists.txt` 文件中定义的所有目标名称。

11. **检查 CMake 子项目是否找到 (`CMakeSubproject.found_method`):**
    - 功能：检查 CMake 子项目是否成功集成。
    - 逻辑推理：如果 `subproject` 方法调用成功，则此方法返回 `True`，否则返回 `False`。

**与逆向方法的关系及举例说明:**

逆向工程经常需要使用各种工具和库来分析和操作二进制文件。这些工具和库很多时候是使用 CMake 构建的。`cmake.py` 模块使得在 Frida 的构建过程中集成这些 CMake 构建的组件变得容易。

**举例说明：**

假设你想在 Frida 中使用一个名为 `Capstone` 的反汇编库，该库使用 CMake 构建。你可以这样做：

1. **在 Frida 的 `meson.build` 文件中添加 CMake 子项目:**

   ```python
   capstone_proj = cmake.subproject('path/to/capstone')
   capstone_dep = capstone_proj.dependency('capstone') # 假设 Capstone 的 CMake 将其库目标命名为 'capstone'
   ```

2. **在你的 Frida 模块中使用 Capstone:**

   ```python
   frida_module = library('my_frida_module',
       'my_frida_module.c',
       dependencies: [frida_dep, capstone_dep],
       # ... 其他选项
   )
   ```

   在这个例子中，`cmake.subproject` 负责调用 CMake 构建 `Capstone` 库。`capstone_proj.dependency('capstone')` 获取了 `Capstone` 构建出的库的依赖信息，然后在 `my_frida_module` 的构建中使用了这个依赖。这样，你的 Frida 模块就可以链接到 `Capstone` 库，并使用其反汇编功能。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

1. **`detect_voidp_size` 函数:**  该函数用于检测 `void*` 指针的大小。这对于确保不同构建组件之间的 ABI 兼容性至关重要，尤其是在处理二进制数据和内存地址时。不同的架构（如 32 位和 64 位）`void*` 的大小不同。

2. **CMake 子项目可能涉及平台特定的编译选项:** 例如，一个用于分析 Linux 内核的 CMake 库可能需要特定的头文件路径或编译标志。通过 `subproject_options` 可以传递这些选项。

   ```python
   kernel_analysis_options = cmake.subproject_options()
   kernel_analysis_options.add_cmake_defines({'KERNEL_HEADERS': '/usr/src/linux-headers-$(uname -r)'})
   kernel_analysis_proj = cmake.subproject('path/to/kernel-analysis-lib', options: kernel_analysis_options)
   ```

3. **CMake 子项目可能构建与 Android 框架交互的库:**  在 Frida 中注入到 Android 进程时，可能需要与 Android 的系统服务或框架进行交互。相关的库可能使用 CMake 构建，并且需要链接到 Android SDK 或 NDK 中的特定库。

**逻辑推理的假设输入与输出:**

**示例：`write_basic_package_version_file`**

* **假设输入:**
    ```python
    cmake.write_basic_package_version_file(
        name: 'MyAwesomeLib',
        version: '2.0.1',
        compatibility: 'SameMajorVersion',
        install_dir: 'lib/cmake/MyAwesomeLib'
    )
    ```
* **预期输出:** 在构建目录中生成一个名为 `MyAwesomeLibConfigVersion.cmake` 的文件，其内容类似于：
    ```cmake
    ####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
    ####### Any changes to this file will be overwritten by the next CMake run ####
    ####### The input file was  ########

    get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

    # Use original install prefix when loaded through a "/usr move"
    # cross-prefix symbolic link such as /lib -> /usr/lib.
    get_filename_component(_realCurr "${CMAKE_CURRENT_LIST_DIR}" REALPATH)
    get_filename_component(_realOrig "/prefix/lib/cmake/MyAwesomeLib" REALPATH) # 假设安装前缀为 /prefix
    if(_realCurr STREQUAL _realOrig)
      set(PACKAGE_PREFIX_DIR "/prefix")
    endif()
    unset(_realOrig)
    unset(_realCurr)

    macro(set_and_check _var _file)
      set(${_var} "${_file}")
      if(NOT EXISTS "${_file}")
        message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
      endif()
    endmacro()

    ####################################################################################

    set(PACKAGE_VERSION "2.0.1")
    set(PACKAGE_VERSION_MAJOR "2")
    set(PACKAGE_VERSION_MINOR "0")
    set(PACKAGE_VERSION_PATCH "1")

    if("${PACKAGE_VERSION_MAJOR}" STREQUAL "2")
      set(PACKAGE_VERSION_COMPATIBILITY SameMajorVersion)
    endif()
    ```

**涉及用户或者编程常见的使用错误及举例说明:**

1. **在 `configure_package_config_file` 中配置字典的键与模板文件中的变量名不匹配:**

   ```python
   # meson.build
   cmake.configure_package_config_file(
       input: 'MyConfig.cmake.in',
       output: 'MyConfig.cmake',
       configuration: {'MY_VAR': 'some_value'}
   )
   ```

   如果 `MyConfig.cmake.in` 中使用的是 `@OTHER_VAR@` 而不是 `@MY_VAR@`，则替换不会发生，最终生成的配置文件可能不正确。

2. **在 `subproject` 中指定错误的 CMake 子项目路径:**

   ```python
   cmake.subproject('../wrong/path/to/cmake_project') # 如果该路径下没有 CMakeLists.txt
   ```

   这会导致 Meson 尝试构建一个不存在的 CMake 项目，从而失败。

3. **在 `CMakeSubproject.dependency` 中使用了错误的 CMake 目标名称:**

   ```python
   capstone_proj = cmake.subproject('path/to/capstone')
   capstone_dep = capstone_proj.dependency('incorrect_target_name') # 如果 Capstone 中没有名为 'incorrect_target_name' 的库目标
   ```

   这会导致 Meson 无法找到指定的依赖项。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

当 Frida 的开发者或者贡献者在开发过程中需要集成一个基于 CMake 的外部库或者模块时，他们会在 Frida 的 `meson.build` 文件中使用 `cmake` 模块提供的函数。

1. **编辑 `meson.build` 文件:** 用户会打开 Frida 源代码树中的 `meson.build` 文件（或者其他相关的 `meson.build` 文件）。

2. **使用 `cmake.subproject()` 添加 CMake 子项目:**  为了将一个 CMake 项目纳入构建，用户会调用 `cmake.subproject()` 函数，并提供 CMake 项目的路径。例如：

   ```python
   my_cmake_lib = cmake.subproject('path/to/my-cmake-library')
   ```

3. **配置 CMake 子项目选项 (可选):**  如果需要自定义 CMake 子项目的构建选项，用户可能会使用 `cmake.subproject_options()` 创建一个选项对象，并使用其方法设置选项，然后将其传递给 `cmake.subproject()`：

   ```python
   cmake_opts = cmake.subproject_options()
   cmake_opts.add_cmake_defines({'MY_CUSTOM_FLAG': 'ON'})
   my_cmake_lib = cmake.subproject('path/to/my-cmake-library', options: cmake_opts)
   ```

4. **使用 CMake 子项目的目标或依赖:**  一旦 CMake 子项目被添加，用户可以使用 `CMakeSubproject` 对象的方法来获取其构建产物，例如库依赖、包含目录等，并将它们链接到 Frida 的其他组件：

   ```python
   my_cmake_lib = cmake.subproject('path/to/my-cmake-library')
   my_cmake_dep = my_cmake_lib.dependency('MyCMakeLibrary') # 假设 CMake 项目构建了一个名为 MyCMakeLibrary 的库

   frida_module = library('my_frida_module',
       'my_frida_module.c',
       dependencies: [frida_dep, my_cmake_dep],
       # ...
   )
   ```

5. **运行 Meson 构建命令:**  当用户运行 `meson setup build` 或 `ninja` 命令来构建 Frida 时，Meson 会解析 `meson.build` 文件，遇到 `cmake.subproject()` 等调用时，就会执行 `cmake.py` 模块中的相应代码。

**作为调试线索：**

如果在 Frida 的构建过程中遇到了与 CMake 集成相关的问题（例如，CMake 子项目构建失败，找不到依赖等），开发者可以查看 Meson 的构建日志，其中会包含 `cmake.py` 模块执行的详细信息，例如 CMake 的调用命令、输出等。此外，检查 `meson.build` 文件中对 `cmake` 模块的使用是否正确，例如路径是否正确，依赖目标名称是否匹配等，也是重要的调试步骤。

总结来说，`frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/cmake.py` 文件是 Frida 构建系统中用于集成 CMake 项目的关键模块，它通过 Meson 提供了对 CMake 构建流程的封装和控制，使得在 Frida 项目中使用基于 CMake 的组件变得更加方便。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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