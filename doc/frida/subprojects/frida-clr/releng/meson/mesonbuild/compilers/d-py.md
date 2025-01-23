Response:
Let's break down the thought process for analyzing this Python code snippet.

1. **Understand the Goal:** The request asks for an analysis of a specific Python file within the Frida project, focusing on its functionality, relevance to reverse engineering, interaction with low-level concepts, logical reasoning, potential user errors, debugging context, and a summary of its core function.

2. **Identify the Core Function:** The filename `d.py` and the imports like `Compiler`, `GnuCompiler`, and `DmdLikeCompilerMixin` strongly suggest this file defines compiler classes specifically for the D programming language within the Meson build system. The presence of `frida-clr` in the path hints this is used in the context of Frida's .NET/CLR support, which itself is relevant to dynamic instrumentation and reverse engineering.

3. **Analyze Imports:** The imports provide crucial clues about the file's purpose and dependencies:
    * `os.path`, `subprocess`:  Indicates interaction with the file system and running external processes (compilers).
    * `re`:  Suggests parsing output from compiler executions, likely for version information.
    * `typing`: Type hints for better code readability and static analysis.
    * `mesonlib`: Core Meson library functions.
    * `arglist.CompilerArgs`:  Handling of compiler command-line arguments.
    * `linkers.RSPFileSyntax`:  Dealing with response files for large command lines.
    * `.compilers`:  Importing the base `Compiler` class and related functionalities within Meson's compiler framework.
    * `.mixins.gnu`:  Reusing functionality specific to GNU-like compilers (GCC, GDC).
    * `.build.DFeatures`:  Handling D-specific compiler features.
    * `.dependencies.Dependency`: Representing external dependencies.
    * `.envconfig.MachineInfo`: Information about the target machine.
    * `.environment.Environment`: The overall Meson build environment.
    * `.linkers.linkers.DynamicLinker`:  Interaction with the system linker.
    * `.mesonlib.MachineChoice`:  Specifying the target architecture.

4. **Examine Class Definitions:** The file defines several classes:
    * `DmdLikeCompilerMixin`:  Abstracts common logic for DMD and LDC (D compilers). This immediately tells us the code aims for some level of reusability.
    * `DCompilerArgs`: A custom class for handling D compiler arguments, suggesting specific requirements for argument processing.
    * `DCompiler`: The base class for D compilers within Meson. This is where the core functionality of interacting with the D compiler resides.
    * `GnuDCompiler`: A specialization for the GDC compiler (GNU D Compiler), inheriting from both `GnuCompiler` and `DCompiler`. This highlights the use of GDC within the Frida project.
    * `LLVMDCompiler`: A specialization for the LDC compiler (LLVM-based D Compiler), inheriting from `DmdLikeCompilerMixin` and `DCompiler`.
    * `DmdDCompiler`: A specialization for the DMD compiler (Digital Mars D Compiler), inheriting from `DmdLikeCompilerMixin` and `DCompiler`.

5. **Analyze Key Methods within Classes:**  Focus on the purpose of individual methods:
    * `__init__`: Constructor to initialize compiler instances, storing the compiler executable path, version, and target machine info.
    * `sanity_check`: Verifies if the compiler is working correctly by attempting a simple compilation and execution.
    * `get_output_args`, `get_linker_output_args`:  Methods to construct the output file argument for the compiler and linker, respectively.
    * `get_include_args`:  Constructing include directory arguments.
    * `compute_parameters_with_absolute_paths`:  Ensuring paths are absolute, important for build system consistency.
    * `get_warn_args`, `get_werror_args`: Handling compiler warnings and treating them as errors.
    * `get_coverage_args`: Enabling code coverage instrumentation.
    * `get_preprocess_only_args`, `get_compile_only_args`:  Controlling the compilation process.
    * `get_depfile_suffix`, `get_dependency_gen_args`: Managing dependency tracking for incremental builds.
    * `get_pic_args`: Generating position-independent code, crucial for shared libraries.
    * `get_optimization_link_args`, `get_optimization_args`:  Setting optimization levels.
    * `gen_import_library_args`: Creating import libraries on Windows.
    * `build_rpath_args`:  Managing runtime library paths, essential for shared library loading.
    * `_translate_args_to_nongnu`, `translate_arg_to_windows`, `_translate_arg_to_osx`: Handling platform-specific argument translations, crucial for cross-compilation.
    * `get_debug_args`: Adding debug symbols.
    * `get_soname_args`: Setting the shared object name.
    * `get_allow_undefined_link_args`:  Allowing undefined symbols during linking (can be risky).
    * `get_feature_args`: Handling D-specific features like unit tests, debug flags, and version flags.
    * `has_multi_arguments`: Checking if the compiler supports combining arguments.
    * `get_crt_compile_args`, `get_crt_link_args`: Handling C runtime library linking.
    * `run`, `compiles`, `sizeof`, `alignment`, `has_header`:  Core Meson functions for interacting with the compiler to check properties of the target environment.

6. **Connect to Reverse Engineering:**  Consider how the compiler interactions facilitate Frida's dynamic instrumentation:
    * **Compilation of Frida components:** This code is part of building Frida itself, which is the core tool for dynamic instrumentation.
    * **Targeting specific architectures:** The architecture-specific flags (`-m64`, `-m32`) and the cross-compilation logic are essential for Frida to target different platforms (Linux, Android, Windows).
    * **Debug symbols:** The `get_debug_args` method is directly relevant to generating debug information, which is crucial for reverse engineering and understanding program behavior.
    * **Shared libraries:**  The `get_pic_args`, `build_rpath_args`, and `get_soname_args` methods are all about managing shared libraries, which are a key aspect of how Frida injects code into target processes.
    * **Conditional compilation:** The `get_feature_args` for debug and version flags allow for building Frida with different configurations, which can be useful in reverse engineering scenarios.

7. **Identify Low-Level/Kernel/Framework Interactions:** Look for code dealing with platform-specific features and linking:
    * **Windows-specific arguments:** The `translate_arg_to_windows` method and the handling of `-mscrtlib` clearly show interaction with the Windows C runtime.
    * **macOS-specific arguments:** `_translate_arg_to_osx` shows handling of macOS-specific linker options like `-install_name`.
    * **`-fPIC`:**  The use of `-fPIC` is fundamental for creating shared libraries on Linux and Android.
    * **`-rpath`:**  Managing runtime library search paths is a core operating system concept.

8. **Infer Logical Reasoning:**  Analyze conditional logic and assumptions:
    * **Version comparison:** The `version_compare` function is used to determine compiler capabilities based on its version.
    * **Feature detection:** The code checks for the presence of certain compiler features (like `-funittest`) before using them.
    * **Platform-specific handling:**  The `if info.is_windows():` blocks demonstrate conditional logic based on the target operating system.

9. **Consider User Errors:** Think about common mistakes when using build systems:
    * **Incorrect paths:**  The `compute_parameters_with_absolute_paths` method addresses potential issues with relative paths.
    * **Unsupported compiler versions:**  The version checks can lead to errors if an incompatible compiler is used.
    * **Missing dependencies:** While not directly in this file, the concept of dependencies is present, and users could have issues with missing libraries.

10. **Trace User Interaction (Debugging):** Imagine how a developer might end up looking at this file:
    * **Build failures:** If there are issues during the compilation of Frida's .NET/CLR support, a developer might trace the build process and end up in this file, looking at how the D compiler is being invoked.
    * **Investigating compiler flags:** If specific D compiler flags are needed or causing issues, a developer might examine this file to see how those flags are being constructed.
    * **Cross-compilation problems:**  Issues when building Frida for a different target architecture could lead a developer to investigate the platform-specific argument handling.

11. **Synthesize the Summary:**  Based on the analysis, formulate a concise summary of the file's purpose. Focus on its role in the Frida build process, its interaction with D compilers, and its relevance to dynamic instrumentation.

**(Self-Correction/Refinement):** Initially, I might focus too much on the individual compiler classes (GnuDCompiler, LLVMDCompiler, DmdDCompiler). While important, the core function lies in the base `DCompiler` class and the shared logic in `DmdLikeCompilerMixin`. The initial summary should reflect this hierarchical structure and the overall purpose of providing a D compiler interface for Meson within Frida. Also, initially I might not explicitly connect every single method to reverse engineering. During refinement, I need to make those connections more explicit.
好的，让我们来分析一下 `frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/d.py` 这个文件的功能。

**核心功能：定义和管理 D 语言编译器在 Meson 构建系统中的集成**

这个 Python 文件是 Frida 项目中用于处理 D 语言编译器的模块，它是 Meson 构建系统的一部分。它的主要目的是提供一个抽象层，使得 Meson 可以与不同的 D 语言编译器（如 DMD, LDC, GDC）进行交互，并管理编译过程中的各种细节。

**具体功能分解：**

1. **定义 D 语言编译器的通用接口 (`DCompiler` 类):**
   - 它继承自 Meson 的 `Compiler` 基类，定义了 D 语言编译器所需的一些通用方法和属性，例如：
     - `language = 'd'`:  明确标识这是一个 D 语言编译器。
     - `__init__`: 初始化编译器实例，存储编译器可执行文件路径、版本、目标机器信息等。
     - `sanity_check`:  执行基本的编译器健康检查，确保编译器可以正常工作。
     - `needs_static_linker`:  表明 D 语言编译通常需要静态链接器。
     - `get_depfile_suffix`:  获取依赖文件（`.deps`）的后缀。
     - `get_pic_args`:  获取生成位置无关代码（PIC）的参数。
     - `get_feature_args`:  处理 D 语言特定的特性参数，例如单元测试、debug 和 version 标识符、import 目录等。
     - `get_optimization_link_args`: 获取链接时的优化参数。
     - `compiler_args`:  返回 `DCompilerArgs` 实例，用于处理编译器参数。
     - `has_multi_arguments`: 检查编译器是否支持将多个参数合并为一个。
     - `_get_target_arch_args`:  获取目标架构相关的参数（例如 `-m64`, `-m32`）。
     - `get_crt_compile_args`, `get_crt_link_args`: 获取与 C 运行时库相关的编译和链接参数。
     - `run`, `sizeof`, `alignment`, `has_header`:  封装了编译和运行代码片段，用于获取类型大小、对齐方式以及检查头文件是否存在。

2. **定义不同 D 语言编译器的特定实现 (继承自 `DCompiler`):**
   - **`GnuDCompiler` (用于 GDC):**
     - 继承自 `GnuCompiler` 和 `DCompiler`，利用了 GNU 编译器的通用特性。
     - 提供了 GDC 特定的警告参数、优化参数等。
     - 重写了 `compute_parameters_with_absolute_paths` 方法来处理 GDC 的路径格式。
     - 增加了 `-shared-libphobos` 链接参数。
   - **`LLVMDCompiler` (用于 LDC):**
     - 继承自 `DmdLikeCompilerMixin` 和 `DCompiler`，因为它与 DMD 有一些相似之处。
     - 提供了 LDC 特定的颜色输出参数、警告参数、PIC 参数、优化参数等。
     - 实现了 `unix_args_to_native` 方法来进行参数转换。
     - 增加了 `-link-defaultlib-shared` 链接参数。
     - 定义了 LDC 使用的响应文件语法 (`rsp_file_syntax`)。
   - **`DmdDCompiler` (用于 DMD):**
     - 继承自 `DmdLikeCompilerMixin` 和 `DCompiler`。
     - 提供了 DMD 特定的颜色输出参数。
     - 针对 Windows 平台，在链接标准可执行文件时添加了必要的库。

3. **提供 DMD-like 编译器的混合类 (`DmdLikeCompilerMixin`):**
   - 用于共享 DMD 和 LDC 之间的一些共同特性，例如：
     - 处理依赖文件生成 (`-makedeps`)。
     - 获取输出文件名的参数 (`-of`)。
     - 获取包含目录的参数 (`-I`)。
     - 处理链接库的参数 (`-L`)。
     - 处理警告和错误参数 (`-wi`, `-w`)。
     - 处理代码覆盖率参数 (`-cov`)。
     - 处理预处理和编译参数 (`-E`, `-c`)。
     - 处理 PIC 参数 (`-fPIC`)。
     - 处理 RPATH 参数。
     - 提供了将通用参数转换为非 GNU 风格参数的方法 (`_translate_args_to_nongnu`)，以及针对 Windows 和 macOS 的特定参数转换方法。
     - 处理 debug 和 soname 参数。

4. **定义 D 语言编译器参数类 (`DCompilerArgs`):**
   - 继承自 `CompilerArgs`，定义了 D 语言编译器参数的一些特殊处理规则，例如前缀 (`-I`, `-L`) 和去重规则。

5. **定义 D 语言特性参数的字典 (`d_feature_args`):**
   - 存储了不同 D 语言编译器（gcc, llvm, dmd）支持的特性参数，例如单元测试 (`-funittest`, `-unittest`)、debug 标识符 (`-fdebug`, `-d-debug`, `-debug`)、版本标识符 (`-fversion`, `-d-version`, `-version`) 和 import 目录 (`-J`)。

6. **定义不同编译器和优化级别的优化参数字典 (`ldc_optimization_args`, `dmd_optimization_args`, `gdc_optimization_args`):**
   - 存储了不同 D 语言编译器在不同优化级别下使用的命令行参数。

7. **辅助函数 (`find_ldc_dmd_frontend_version`):**
   - 用于从 LDC 的版本输出中提取 DMD 前端版本信息，以便确定 LDC 兼容的 DMD 功能。

**与逆向方法的关系及举例说明：**

这个文件直接支持了 Frida 的构建过程，而 Frida 本身是一个动态插桩工具，广泛应用于软件逆向工程。

* **编译带有调试信息的 Frida 组件:**  `get_debug_args` 方法在构建 Frida 时会被调用，以添加调试符号，这对于逆向 Frida 自身或者使用 Frida 去调试其他程序至关重要。例如，当开发者想要深入了解 Frida 的内部工作原理时，就需要编译带有调试符号的 Frida。Meson 会调用 `get_debug_args` 获取 `-g` (对于 GDC) 或 `-d-debug` (对于 LDC) 等参数。
* **支持特定的 D 语言特性:**  `get_feature_args` 允许启用或禁用 D 语言的特定特性，例如单元测试。虽然单元测试更多用于开发阶段，但在某些逆向场景中，理解目标程序是否使用了某些 D 语言特性可能是有帮助的。
* **处理不同 D 语言编译器的差异:**  由于不同的 D 语言编译器在语法和命令行选项上存在差异，这个文件通过定义不同的编译器类来处理这些差异，确保 Frida 可以在不同的 D 语言环境下构建。这对于逆向基于 D 语言的程序非常重要，因为你需要了解目标程序是用哪个编译器编译的。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

* **位置无关代码 (PIC):** `get_pic_args` 方法返回 `-fPIC` 参数，这对于构建共享库是必需的。Frida 经常需要将自身注入到目标进程中，而注入的代码通常需要是位置无关的，才能在不同的内存地址上运行。
* **RPATH 处理:** `build_rpath_args` 方法用于设置运行时库的搜索路径。在 Linux 和 Android 等系统中，RPATH 对于确保程序在运行时能够找到依赖的共享库至关重要。Frida 在注入目标进程后，可能需要加载一些共享库，RPATH 的设置就变得非常重要。
* **目标架构参数 (`_get_target_arch_args`):**  对于交叉编译 Frida（例如，在 x86_64 机器上构建运行在 ARM 架构 Android 上的 Frida），需要指定目标架构。`_get_target_arch_args` 方法会根据目标机器信息返回相应的编译器参数（例如，`-m64` 或 `-m32`）。
* **C 运行时库 (CRT) 处理:** `get_crt_compile_args` 和 `get_crt_link_args` 用于处理与 C 运行时库的链接。在不同的操作系统和编译环境下，需要链接不同的 CRT 库。例如，在 Windows 上，可能需要链接 `msvcrt` 或 `libcmt` 等。

**逻辑推理及假设输入与输出：**

* **`get_optimization_args` 的逻辑推理：**
    - **假设输入:** `optimization_level = '2'`, `self.id = 'llvm'`
    - **推理:**  根据 `ldc_optimization_args` 字典，优化级别 '2' 对应 `['-O2', '-enable-inlining', '-Hkeep-all-bodies']`。由于 `self.id` 是 'llvm'，所以会从 `ldc_optimization_args` 中查找。
    - **输出:** `['-O2', '-enable-inlining', '-Hkeep-all-bodies']`
* **`get_feature_args` 中处理 debug 标识符的逻辑：**
    - **假设输入:** `kwargs['debug'] = ['MY_DEBUG', 1]`, `self.id = 'gcc'`
    - **推理:**  遍历 `kwargs['debug']`，如果是字符串则直接添加 `-fdebug=MY_DEBUG`，如果是数字则添加 `-fdebug=1`。
    - **输出:** `['-funittest', '-fdebug=MY_DEBUG', '-fdebug=1']` (假设 `kwargs['unittest']` 为 True)

**涉及用户或编程常见的使用错误及举例说明：**

* **编译器路径配置错误:**  如果用户没有正确配置 D 语言编译器的路径，Meson 在执行 `sanity_check` 时会失败，抛出 `EnvironmentException`，提示编译器无法执行。
* **依赖缺失:**  如果构建 Frida 所需的 D 语言库或依赖不存在，链接过程会失败。虽然这个文件本身不直接处理依赖安装，但它生成的链接命令会因为找不到依赖而报错。
* **使用了不受支持的编译器版本:**  某些编译器特性可能只在特定版本中可用。如果用户使用了过旧的编译器，Meson 可能会因为找不到相应的编译器参数而报错，或者构建出的 Frida 功能不完整。例如，较旧的 GDC 可能不支持某些 `-W` 警告选项。
* **交叉编译环境配置错误:**  进行交叉编译时，用户可能没有正确配置目标平台的工具链和库，导致编译器或链接器找不到必要的头文件或库文件。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户尝试构建 Frida:**  用户执行了 Frida 的构建命令，例如 `meson setup build` 或 `ninja -C build`。
2. **Meson 配置阶段:** Meson 会读取 `meson.build` 文件，其中会声明 Frida 依赖于 D 语言。
3. **D 语言编译器检测:** Meson 会尝试检测系统中可用的 D 语言编译器（DMD, LDC, GDC）。
4. **进入 `d.py` 模块:**  Meson 需要知道如何与检测到的 D 语言编译器进行交互，因此会加载 `frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/d.py` 文件。
5. **编译器类实例化:**  Meson 会根据检测到的编译器类型实例化相应的编译器类（例如 `GnuDCompiler`, `LLVMDCompiler`, `DmdDCompiler`）。
6. **执行编译器检查:** Meson 可能会调用 `sanity_check` 方法来验证编译器的基本功能。
7. **构建目标:**  当需要编译 D 语言源代码时，Meson 会调用这个文件中定义的各种方法来生成正确的编译器命令行参数，例如 `get_output_args` 获取输出文件名，`get_include_args` 获取包含目录，`get_feature_args` 获取特性参数等。

**调试线索：**

* 如果构建过程中出现与 D 语言编译相关的错误，开发者可能会检查这个文件，查看 Meson 是如何构建 D 语言编译命令的。
* 如果需要调整 D 语言编译器的特定选项，开发者可能会修改这个文件或者查找相关的 Meson 配置选项。
* 当支持新的 D 语言编译器或者需要处理特定编译器的 bug 时，开发者会深入研究这个文件的代码。

**功能归纳 (第 1 部分):**

这个 Python 文件在 Frida 项目的 Meson 构建系统中扮演着**核心的 D 语言编译器集成角色**。它通过定义通用的 `DCompiler` 类以及针对不同 D 语言编译器的特定实现，使得 Meson 能够**抽象并管理 D 语言的编译过程**。其主要功能包括：**定义编译器接口、处理编译器参数、生成编译命令、执行编译器检查、以及处理不同编译器之间的差异**。这对于确保 Frida 可以在不同的 D 语言环境下成功构建至关重要，同时也为 Frida 的动态插桩功能提供了必要的编译支持。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/d.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2022 The Meson development team

from __future__ import annotations

import os.path
import re
import subprocess
import typing as T

from .. import mesonlib
from ..arglist import CompilerArgs
from ..linkers import RSPFileSyntax
from ..mesonlib import (
    EnvironmentException, version_compare, OptionKey, is_windows
)

from . import compilers
from .compilers import (
    clike_debug_args,
    Compiler,
    CompileCheckMode,
)
from .mixins.gnu import GnuCompiler
from .mixins.gnu import gnu_common_warning_args

if T.TYPE_CHECKING:
    from ..build import DFeatures
    from ..dependencies import Dependency
    from ..envconfig import MachineInfo
    from ..environment import Environment
    from ..linkers.linkers import DynamicLinker
    from ..mesonlib import MachineChoice

    CompilerMixinBase = Compiler
else:
    CompilerMixinBase = object

d_feature_args: T.Dict[str, T.Dict[str, str]] = {
    'gcc':  {
        'unittest': '-funittest',
        'debug': '-fdebug',
        'version': '-fversion',
        'import_dir': '-J'
    },
    'llvm': {
        'unittest': '-unittest',
        'debug': '-d-debug',
        'version': '-d-version',
        'import_dir': '-J'
    },
    'dmd':  {
        'unittest': '-unittest',
        'debug': '-debug',
        'version': '-version',
        'import_dir': '-J'
    }
}

ldc_optimization_args: T.Dict[str, T.List[str]] = {
    'plain': [],
    '0': [],
    'g': [],
    '1': ['-O1'],
    '2': ['-O2', '-enable-inlining', '-Hkeep-all-bodies'],
    '3': ['-O3', '-enable-inlining', '-Hkeep-all-bodies'],
    's': ['-Oz'],
}

dmd_optimization_args: T.Dict[str, T.List[str]] = {
    'plain': [],
    '0': [],
    'g': [],
    '1': ['-O'],
    '2': ['-O', '-inline'],
    '3': ['-O', '-inline'],
    's': ['-O'],
}

gdc_optimization_args: T.Dict[str, T.List[str]] = {
    'plain': [],
    '0': ['-O0'],
    'g': ['-Og'],
    '1': ['-O1'],
    '2': ['-O2', '-finline-functions'],
    '3': ['-O3', '-finline-functions'],
    's': ['-Os'],
}


class DmdLikeCompilerMixin(CompilerMixinBase):

    """Mixin class for DMD and LDC.

    LDC has a number of DMD like arguments, and this class allows for code
    sharing between them as makes sense.
    """

    def __init__(self, dmd_frontend_version: T.Optional[str]):
        if dmd_frontend_version is None:
            self._dmd_has_depfile = False
        else:
            # -makedeps switch introduced in 2.095 frontend
            self._dmd_has_depfile = version_compare(dmd_frontend_version, ">=2.095.0")

    if T.TYPE_CHECKING:
        mscrt_args: T.Dict[str, T.List[str]] = {}

        def _get_target_arch_args(self) -> T.List[str]: ...

    LINKER_PREFIX = '-L='

    def get_output_args(self, outputname: str) -> T.List[str]:
        return ['-of=' + outputname]

    def get_linker_output_args(self, outputname: str) -> T.List[str]:
        return ['-of=' + outputname]

    def get_include_args(self, path: str, is_system: bool) -> T.List[str]:
        if path == "":
            path = "."
        return ['-I=' + path]

    def compute_parameters_with_absolute_paths(self, parameter_list: T.List[str],
                                               build_dir: str) -> T.List[str]:
        for idx, i in enumerate(parameter_list):
            if i[:3] == '-I=':
                parameter_list[idx] = i[:3] + os.path.normpath(os.path.join(build_dir, i[3:]))
            if i[:4] == '-L-L':
                parameter_list[idx] = i[:4] + os.path.normpath(os.path.join(build_dir, i[4:]))
            if i[:5] == '-L=-L':
                parameter_list[idx] = i[:5] + os.path.normpath(os.path.join(build_dir, i[5:]))
            if i[:6] == '-Wl,-L':
                parameter_list[idx] = i[:6] + os.path.normpath(os.path.join(build_dir, i[6:]))

        return parameter_list

    def get_warn_args(self, level: str) -> T.List[str]:
        return ['-wi']

    def get_werror_args(self) -> T.List[str]:
        return ['-w']

    def get_coverage_args(self) -> T.List[str]:
        return ['-cov']

    def get_coverage_link_args(self) -> T.List[str]:
        return []

    def get_preprocess_only_args(self) -> T.List[str]:
        return ['-E']

    def get_compile_only_args(self) -> T.List[str]:
        return ['-c']

    def get_depfile_suffix(self) -> str:
        return 'deps'

    def get_dependency_gen_args(self, outtarget: str, outfile: str) -> T.List[str]:
        if self._dmd_has_depfile:
            return [f'-makedeps={outfile}']
        return []

    def get_pic_args(self) -> T.List[str]:
        if self.info.is_windows():
            return []
        return ['-fPIC']

    def get_optimization_link_args(self, optimization_level: str) -> T.List[str]:
        if optimization_level != 'plain':
            return self._get_target_arch_args()
        return []

    def gen_import_library_args(self, implibname: str) -> T.List[str]:
        return self.linker.import_library_args(implibname)

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        if self.info.is_windows():
            return ([], set())

        # GNU ld, solaris ld, and lld acting like GNU ld
        if self.linker.id.startswith('ld'):
            # The way that dmd and ldc pass rpath to gcc is different than we would
            # do directly, each argument -rpath and the value to rpath, need to be
            # split into two separate arguments both prefaced with the -L=.
            args: T.List[str] = []
            (rpath_args, rpath_dirs_to_remove) = super().build_rpath_args(
                    env, build_dir, from_dir, rpath_paths, build_rpath, install_rpath)
            for r in rpath_args:
                if ',' in r:
                    a, b = r.split(',', maxsplit=1)
                    args.append(a)
                    args.append(self.LINKER_PREFIX + b)
                else:
                    args.append(r)
            return (args, rpath_dirs_to_remove)

        return super().build_rpath_args(
            env, build_dir, from_dir, rpath_paths, build_rpath, install_rpath)

    @classmethod
    def _translate_args_to_nongnu(cls, args: T.List[str], info: MachineInfo, link_id: str) -> T.List[str]:
        # Translate common arguments to flags the LDC/DMD compilers
        # can understand.
        # The flags might have been added by pkg-config files,
        # and are therefore out of the user's control.
        dcargs: T.List[str] = []
        # whether we hit a linker argument that expect another arg
        # see the comment in the "-L" section
        link_expect_arg = False
        link_flags_with_arg = [
            '-rpath', '-rpath-link', '-soname', '-compatibility_version', '-current_version',
        ]
        for arg in args:
            # Translate OS specific arguments first.
            osargs: T.List[str] = []
            if info.is_windows():
                osargs = cls.translate_arg_to_windows(arg)
            elif info.is_darwin():
                osargs = cls._translate_arg_to_osx(arg)
            if osargs:
                dcargs.extend(osargs)
                continue

            # Translate common D arguments here.
            if arg == '-pthread':
                continue
            if arg.startswith('-fstack-protector'):
                continue
            if arg.startswith('-D') and not (arg == '-D' or arg.startswith(('-Dd', '-Df'))):
                # ignore all '-D*' flags (like '-D_THREAD_SAFE')
                # unless they are related to documentation
                continue
            if arg.startswith('-Wl,'):
                # Translate linker arguments here.
                linkargs = arg[arg.index(',') + 1:].split(',')
                for la in linkargs:
                    dcargs.append('-L=' + la.strip())
                continue
            elif arg.startswith(('-link-defaultlib', '-linker', '-link-internally', '-linkonce-templates', '-lib')):
                # these are special arguments to the LDC linker call,
                # arguments like "-link-defaultlib-shared" do *not*
                # denote a library to be linked, but change the default
                # Phobos/DRuntime linking behavior, while "-linker" sets the
                # default linker.
                dcargs.append(arg)
                continue
            elif arg.startswith('-l'):
                # translate library link flag
                dcargs.append('-L=' + arg)
                continue
            elif arg.startswith('-isystem'):
                # translate -isystem system include path
                # this flag might sometimes be added by C library Cflags via
                # pkg-config.
                # NOTE: -isystem and -I are not 100% equivalent, so this is just
                # a workaround for the most common cases.
                if arg.startswith('-isystem='):
                    dcargs.append('-I=' + arg[9:])
                else:
                    dcargs.append('-I' + arg[8:])
                continue
            elif arg.startswith('-idirafter'):
                # same as -isystem, but appends the path instead
                if arg.startswith('-idirafter='):
                    dcargs.append('-I=' + arg[11:])
                else:
                    dcargs.append('-I' + arg[10:])
                continue
            elif arg.startswith('-L'):
                # The D linker expect library search paths in the form of -L=-L/path (the '=' is optional).
                #
                # This function receives a mix of arguments already prepended
                # with -L for the D linker driver and other linker arguments.
                # The arguments starting with -L can be:
                #  - library search path (with or without a second -L)
                #     - it can come from pkg-config (a single -L)
                #     - or from the user passing linker flags (-L-L would be expected)
                #  - arguments like "-L=-rpath" that expect a second argument (also prepended with -L)
                #  - arguments like "-L=@rpath/xxx" without a second argument (on Apple platform)
                #  - arguments like "-L=/SUBSYSTEM:CONSOLE (for Windows linker)
                #
                # The logic that follows tries to detect all these cases (some may be missing)
                # in order to prepend a -L only for the library search paths with a single -L

                if arg.startswith('-L='):
                    suffix = arg[3:]
                else:
                    suffix = arg[2:]

                if link_expect_arg:
                    # flags like rpath and soname expect a path or filename respectively,
                    # we must not alter it (i.e. prefixing with -L for a lib search path)
                    dcargs.append(arg)
                    link_expect_arg = False
                    continue

                if suffix in link_flags_with_arg:
                    link_expect_arg = True

                if suffix.startswith('-') or suffix.startswith('@'):
                    # this is not search path
                    dcargs.append(arg)
                    continue

                # linker flag such as -L=/DEBUG must pass through
                if info.is_windows() and link_id == 'link' and suffix.startswith('/'):
                    dcargs.append(arg)
                    continue

                # Make sure static library files are passed properly to the linker.
                if arg.endswith('.a') or arg.endswith('.lib'):
                    if len(suffix) > 0 and not suffix.startswith('-'):
                        dcargs.append('-L=' + suffix)
                        continue

                dcargs.append('-L=' + arg)
                continue
            elif not arg.startswith('-') and arg.endswith(('.a', '.lib')):
                # ensure static libraries are passed through to the linker
                dcargs.append('-L=' + arg)
                continue
            else:
                dcargs.append(arg)

        return dcargs

    @classmethod
    def translate_arg_to_windows(cls, arg: str) -> T.List[str]:
        args: T.List[str] = []
        if arg.startswith('-Wl,'):
            # Translate linker arguments here.
            linkargs = arg[arg.index(',') + 1:].split(',')
            for la in linkargs:
                if la.startswith('--out-implib='):
                    # Import library name
                    args.append('-L=/IMPLIB:' + la[13:].strip())
        elif arg.startswith('-mscrtlib='):
            args.append(arg)
            mscrtlib = arg[10:].lower()
            if cls is LLVMDCompiler:
                # Default crt libraries for LDC2 must be excluded for other
                # selected crt options.
                if mscrtlib != 'libcmt':
                    args.append('-L=/NODEFAULTLIB:libcmt')
                    args.append('-L=/NODEFAULTLIB:libvcruntime')

                # Fixes missing definitions for printf-functions in VS2017
                if mscrtlib.startswith('msvcrt'):
                    args.append('-L=/DEFAULTLIB:legacy_stdio_definitions.lib')

        return args

    @classmethod
    def _translate_arg_to_osx(cls, arg: str) -> T.List[str]:
        args: T.List[str] = []
        if arg.startswith('-install_name'):
            args.append('-L=' + arg)
        return args

    @classmethod
    def _unix_args_to_native(cls, args: T.List[str], info: MachineInfo, link_id: str = '') -> T.List[str]:
        return cls._translate_args_to_nongnu(args, info, link_id)

    def get_debug_args(self, is_debug: bool) -> T.List[str]:
        ddebug_args = []
        if is_debug:
            ddebug_args = [d_feature_args[self.id]['debug']]

        return clike_debug_args[is_debug] + ddebug_args

    def _get_crt_args(self, crt_val: str, buildtype: str) -> T.List[str]:
        if not self.info.is_windows():
            return []
        return self.mscrt_args[self.get_crt_val(crt_val, buildtype)]

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str,
                        darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        sargs = super().get_soname_args(env, prefix, shlib_name, suffix,
                                        soversion, darwin_versions)

        # LDC and DMD actually do use a linker, but they proxy all of that with
        # their own arguments
        soargs: T.List[str] = []
        if self.linker.id.startswith('ld.'):
            for arg in sargs:
                a, b = arg.split(',', maxsplit=1)
                soargs.append(a)
                soargs.append(self.LINKER_PREFIX + b)
            return soargs
        elif self.linker.id.startswith('ld64'):
            for arg in sargs:
                if not arg.startswith(self.LINKER_PREFIX):
                    soargs.append(self.LINKER_PREFIX + arg)
                else:
                    soargs.append(arg)
            return soargs
        else:
            return sargs

    def get_allow_undefined_link_args(self) -> T.List[str]:
        args = self.linker.get_allow_undefined_args()
        if self.info.is_darwin():
            # On macOS we're passing these options to the C compiler, but
            # they're linker options and need -Wl, so clang/gcc knows what to
            # do with them. I'm assuming, but don't know for certain, that
            # ldc/dmd do some kind of mapping internally for arguments they
            # understand, but pass arguments they don't understand directly.
            args = [a.replace('-L=', '-Xcc=-Wl,') for a in args]
        return args


class DCompilerArgs(CompilerArgs):
    prepend_prefixes = ('-I', '-L')
    dedup2_prefixes = ('-I', )


class DCompiler(Compiler):
    mscrt_args = {
        'none': ['-mscrtlib='],
        'md': ['-mscrtlib=msvcrt'],
        'mdd': ['-mscrtlib=msvcrtd'],
        'mt': ['-mscrtlib=libcmt'],
        'mtd': ['-mscrtlib=libcmtd'],
    }

    language = 'd'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice,
                 info: 'MachineInfo', arch: str, *,
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None,
                 is_cross: bool = False):
        super().__init__([], exelist, version, for_machine, info, linker=linker,
                         full_version=full_version, is_cross=is_cross)
        self.arch = arch

    def sanity_check(self, work_dir: str, environment: 'Environment') -> None:
        source_name = os.path.join(work_dir, 'sanity.d')
        output_name = os.path.join(work_dir, 'dtest')
        with open(source_name, 'w', encoding='utf-8') as ofile:
            ofile.write('''void main() { }''')
        pc = subprocess.Popen(self.exelist + self.get_output_args(output_name) + self._get_target_arch_args() + [source_name], cwd=work_dir)
        pc.wait()
        if pc.returncode != 0:
            raise EnvironmentException('D compiler %s cannot compile programs.' % self.name_string())
        if environment.need_exe_wrapper(self.for_machine):
            if not environment.has_exe_wrapper():
                # Can't check if the binaries run so we have to assume they do
                return
            cmdlist = environment.exe_wrapper.get_command() + [output_name]
        else:
            cmdlist = [output_name]
        if subprocess.call(cmdlist) != 0:
            raise EnvironmentException('Executables created by D compiler %s are not runnable.' % self.name_string())

    def needs_static_linker(self) -> bool:
        return True

    def get_depfile_suffix(self) -> str:
        return 'deps'

    def get_pic_args(self) -> T.List[str]:
        if self.info.is_windows():
            return []
        return ['-fPIC']

    def get_feature_args(self, kwargs: DFeatures, build_to_src: str) -> T.List[str]:
        res: T.List[str] = []
        unittest_arg = d_feature_args[self.id]['unittest']
        if not unittest_arg:
            raise EnvironmentException('D compiler %s does not support the "unittest" feature.' % self.name_string())
        if kwargs['unittest']:
            res.append(unittest_arg)

        debug_level = -1
        debug_arg = d_feature_args[self.id]['debug']
        if not debug_arg:
            raise EnvironmentException('D compiler %s does not support conditional debug identifiers.' % self.name_string())

        # Parse all debug identifiers and the largest debug level identifier
        for d in kwargs['debug']:
            if isinstance(d, int):
                debug_level = max(debug_level, d)
            elif isinstance(d, str) and d.isdigit():
                debug_level = max(debug_level, int(d))
            else:
                res.append(f'{debug_arg}={d}')

        if debug_level >= 0:
            res.append(f'{debug_arg}={debug_level}')

        version_level = -1
        version_arg = d_feature_args[self.id]['version']
        if not version_arg:
            raise EnvironmentException('D compiler %s does not support conditional version identifiers.' % self.name_string())

        # Parse all version identifiers and the largest version level identifier
        for v in kwargs['versions']:
            if isinstance(v, int):
                version_level = max(version_level, v)
            elif isinstance(v, str) and v.isdigit():
                version_level = max(version_level, int(v))
            else:
                res.append(f'{version_arg}={v}')

        if version_level >= 0:
            res.append(f'{version_arg}={version_level}')

        import_dir_arg = d_feature_args[self.id]['import_dir']
        if not import_dir_arg:
            raise EnvironmentException('D compiler %s does not support the "string import directories" feature.' % self.name_string())
        # TODO: ImportDirs.to_string_list(), but we need both the project source
        # root and project build root for that.
        for idir_obj in kwargs['import_dirs']:
            basedir = idir_obj.get_curdir()
            for idir in idir_obj.get_incdirs():
                bldtreedir = os.path.join(basedir, idir)
                # Avoid superfluous '/.' at the end of paths when d is '.'
                if idir not in ('', '.'):
                    expdir = bldtreedir
                else:
                    expdir = basedir
                srctreedir = os.path.join(build_to_src, expdir)
                res.append(f'{import_dir_arg}{srctreedir}')
                res.append(f'{import_dir_arg}{bldtreedir}')

        return res

    def get_optimization_link_args(self, optimization_level: str) -> T.List[str]:
        if optimization_level != 'plain':
            return self._get_target_arch_args()
        return []

    def compiler_args(self, args: T.Optional[T.Iterable[str]] = None) -> DCompilerArgs:
        return DCompilerArgs(self, args)

    def has_multi_arguments(self, args: T.List[str], env: 'Environment') -> T.Tuple[bool, bool]:
        return self.compiles('int i;\n', env, extra_args=args)

    def _get_target_arch_args(self) -> T.List[str]:
        # LDC2 on Windows targets to current OS architecture, but
        # it should follow the target specified by the MSVC toolchain.
        if self.info.is_windows():
            if self.arch == 'x86_64':
                return ['-m64']
            return ['-m32']
        return []

    def get_crt_compile_args(self, crt_val: str, buildtype: str) -> T.List[str]:
        return []

    def get_crt_link_args(self, crt_val: str, buildtype: str) -> T.List[str]:
        return []

    def _get_compile_extra_args(self, extra_args: T.Union[T.List[str], T.Callable[[CompileCheckMode], T.List[str]], None] = None) -> T.List[str]:
        args = self._get_target_arch_args()
        if extra_args:
            if callable(extra_args):
                extra_args = extra_args(CompileCheckMode.COMPILE)
            if isinstance(extra_args, list):
                args.extend(extra_args)
            elif isinstance(extra_args, str):
                args.append(extra_args)
        return args

    def run(self, code: 'mesonlib.FileOrString', env: 'Environment',
            extra_args: T.Union[T.List[str], T.Callable[[CompileCheckMode], T.List[str]], None] = None,
            dependencies: T.Optional[T.List['Dependency']] = None,
            run_env: T.Optional[T.Dict[str, str]] = None,
            run_cwd: T.Optional[str] = None) -> compilers.RunResult:
        extra_args = self._get_compile_extra_args(extra_args)
        return super().run(code, env, extra_args, dependencies, run_env, run_cwd)

    def sizeof(self, typename: str, prefix: str, env: 'Environment', *,
               extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
               dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[int, bool]:
        if extra_args is None:
            extra_args = []
        t = f'''
        import std.stdio : writeln;
        {prefix}
        void main() {{
            writeln(({typename}).sizeof);
        }}
        '''
        res = self.cached_run(t, env, extra_args=extra_args,
                              dependencies=dependencies)
        if not res.compiled:
            return -1, False
        if res.returncode != 0:
            raise mesonlib.EnvironmentException('Could not run sizeof test binary.')
        return int(res.stdout), res.cached

    def alignment(self, typename: str, prefix: str, env: 'Environment', *,
                  extra_args: T.Optional[T.List[str]] = None,
                  dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[int, bool]:
        if extra_args is None:
            extra_args = []
        t = f'''
        import std.stdio : writeln;
        {prefix}
        void main() {{
            writeln(({typename}).alignof);
        }}
        '''
        res = self.run(t, env, extra_args=extra_args,
                       dependencies=dependencies)
        if not res.compiled:
            raise mesonlib.EnvironmentException('Could not compile alignment test.')
        if res.returncode != 0:
            raise mesonlib.EnvironmentException('Could not run alignment test binary.')
        align = int(res.stdout)
        if align == 0:
            raise mesonlib.EnvironmentException(f'Could not determine alignment of {typename}. Sorry. You might want to file a bug.')
        return align, res.cached

    def has_header(self, hname: str, prefix: str, env: 'Environment', *,
                   extra_args: T.Union[None, T.List[str], T.Callable[['CompileCheckMode'], T.List[str]]] = None,
                   dependencies: T.Optional[T.List['Dependency']] = None,
                   disable_cache: bool = False) -> T.Tuple[bool, bool]:

        extra_args = self._get_compile_extra_args(extra_args)
        code = f'''{prefix}
        import {hname};
        '''
        return self.compiles(code, env, extra_args=extra_args,
                             dependencies=dependencies, mode=CompileCheckMode.COMPILE, disable_cache=disable_cache)

class GnuDCompiler(GnuCompiler, DCompiler):

    # we mostly want DCompiler, but that gives us the Compiler.LINKER_PREFIX instead
    LINKER_PREFIX = GnuCompiler.LINKER_PREFIX
    id = 'gcc'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice,
                 info: 'MachineInfo', arch: str, *,
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None,
                 is_cross: bool = False):
        DCompiler.__init__(self, exelist, version, for_machine, info, arch,
                           linker=linker,
                           full_version=full_version, is_cross=is_cross)
        GnuCompiler.__init__(self, {})
        default_warn_args = ['-Wall', '-Wdeprecated']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args + ['-Wextra'],
                          '3': default_warn_args + ['-Wextra', '-Wpedantic'],
                          'everything': (default_warn_args + ['-Wextra', '-Wpedantic'] +
                                         self.supported_warn_args(gnu_common_warning_args))}

        self.base_options = {
            OptionKey(o) for o in [
             'b_colorout', 'b_sanitize', 'b_staticpic', 'b_vscrt',
             'b_coverage', 'b_pgo', 'b_ndebug']}

        self._has_color_support = version_compare(self.version, '>=4.9')
        # dependencies were implemented before, but broken - support was fixed in GCC 7.1+
        # (and some backported versions)
        self._has_deps_support = version_compare(self.version, '>=7.1')

    def get_colorout_args(self, colortype: str) -> T.List[str]:
        if self._has_color_support:
            super().get_colorout_args(colortype)
        return []

    def get_dependency_gen_args(self, outtarget: str, outfile: str) -> T.List[str]:
        if self._has_deps_support:
            return super().get_dependency_gen_args(outtarget, outfile)
        return []

    def get_warn_args(self, level: str) -> T.List[str]:
        return self.warn_args[level]

    def get_optimization_args(self, optimization_level: str) -> T.List[str]:
        return gdc_optimization_args[optimization_level]

    def compute_parameters_with_absolute_paths(self, parameter_list: T.List[str],
                                               build_dir: str) -> T.List[str]:
        for idx, i in enumerate(parameter_list):
            if i[:2] == '-I' or i[:2] == '-L':
                parameter_list[idx] = i[:2] + os.path.normpath(os.path.join(build_dir, i[2:]))

        return parameter_list

    def get_allow_undefined_link_args(self) -> T.List[str]:
        return self.linker.get_allow_undefined_args()

    def get_linker_always_args(self) -> T.List[str]:
        args = super().get_linker_always_args()
        if self.info.is_windows():
            return args
        return args + ['-shared-libphobos']

    def get_assert_args(self, disable: bool) -> T.List[str]:
        if disable:
            return ['-frelease']
        return []

# LDC uses the DMD frontend code to parse and analyse the code.
# It then uses LLVM for the binary code generation and optimizations.
# This function retrieves the dmd frontend version, which determines
# the common features between LDC and DMD.
# We need the complete version text because the match is not on first line
# of version_output
def find_ldc_dmd_frontend_version(version_output: T.Optional[str]) -> T.Optional[str]:
    if version_output is None:
        return None
    version_regex = re.search(r'DMD v(\d+\.\d+\.\d+)', version_output)
    if version_regex:
        return version_regex.group(1)
    return None

class LLVMDCompiler(DmdLikeCompilerMixin, DCompiler):

    id = 'llvm'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice,
                 info: 'MachineInfo', arch: str, *,
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None,
                 is_cross: bool = False, version_output: T.Optional[str] = None):
        DCompiler.__init__(self, exelist, version, for_machine, info, arch,
                           linker=linker,
                           full_version=full_version, is_cross=is_cross)
        DmdLikeCompilerMixin.__init__(self, dmd_frontend_version=find_ldc_dmd_frontend_version(version_output))
        self.base_options = {OptionKey(o) for o in ['b_coverage', 'b_colorout', 'b_vscrt', 'b_ndebug']}

    def get_colorout_args(self, colortype: str) -> T.List[str]:
        if colortype == 'always':
            return ['-enable-color']
        return []

    def get_warn_args(self, level: str) -> T.List[str]:
        if level in {'2', '3'}:
            return ['-wi', '-dw']
        elif level == '1':
            return ['-wi']
        return []

    def get_pic_args(self) -> T.List[str]:
        return ['-relocation-model=pic']

    def get_crt_link_args(self, crt_val: str, buildtype: str) -> T.List[str]:
        return self._get_crt_args(crt_val, buildtype)

    def unix_args_to_native(self, args: T.List[str]) -> T.List[str]:
        return self._unix_args_to_native(args, self.info, self.linker.id)

    def get_optimization_args(self, optimization_level: str) -> T.List[str]:
        if optimization_level != 'plain':
            return self._get_target_arch_args() + ldc_optimization_args[optimization_level]
        return ldc_optimization_args[optimization_level]

    @classmethod
    def use_linker_args(cls, linker: str, version: str) -> T.List[str]:
        return [f'-linker={linker}']

    def get_linker_always_args(self) -> T.List[str]:
        args = super().get_linker_always_args()
        if self.info.is_windows():
            return args
        return args + ['-link-defaultlib-shared']

    def get_assert_args(self, disable: bool) -> T.List[str]:
        if disable:
            return ['--release']
        return []

    def rsp_file_syntax(self) -> RSPFileSyntax:
        # We use `mesonlib.is_windows` here because we want to know what the
        # build machine is, not the host machine. This really means we would
        # have the Environment not the MachineInfo in the compiler.
        return RSPFileSyntax.MSVC if is_windows() else RSPFileSyntax.GCC


class DmdDCompiler(DmdLikeCompilerMixin, DCompiler):

    id = 'dmd'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice,
                 info: 'MachineInfo', arch: str, *,
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None,
                 is_cross: bool = False):
        DCompiler.__init__(self, exelist, version, for_machine, info, arch,
                           linker=linker,
                           full_version=full_version, is_cross=is_cross)
        DmdLikeCompilerMixin.__init__(self, version)
        self.base_options = {OptionKey(o) for o in ['b_coverage', 'b_colorout', 'b_vscrt', 'b_ndebug']}

    def get_colorout_args(self, colortype: str) -> T.List[str]:
        if colortype == 'always':
            return ['-color=on']
        return []

    def get_std_exe_link_args(self) -> T.List[str]:
        if self.info.is_windows():
            # DMD links against D runtime only when main symbol is found,
            # so these needs to be inserted when linking static D libraries.
            if self.arch == 'x86_64':
```