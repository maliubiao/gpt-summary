Response:
Let's break down the thought process for analyzing this Python code and generating the comprehensive explanation.

1. **Understand the Goal:** The primary goal is to understand what the `cuda.py` file in the Frida project does, particularly in relation to reverse engineering, low-level operations, and potential user errors. The context is a Meson build system module.

2. **High-Level Overview:**  The first step is to recognize that this is a module for the Meson build system, specifically designed to handle CUDA compilation within the Frida project. It's not Frida itself, but a *tool* used during Frida's build process.

3. **Identify Key Components:**  Scan the code for classes, functions, and imports.
    * `CudaModule`:  The main class, inheriting from `NewExtensionModule`. This suggests it adds new functionality to Meson.
    * `min_driver_version`:  A function to determine the minimum required NVIDIA driver version for a given CUDA Toolkit version.
    * `nvcc_arch_flags`, `nvcc_arch_readable`: Functions related to generating architecture-specific flags for the `nvcc` (NVIDIA CUDA Compiler) compiler.
    * Imports: Look at the imported modules. `re` (regular expressions), `typing`, `mesonlib`, `compilers.cuda`, and `interpreter` provide clues about the functionality.

4. **Analyze Each Function:**

    * **`min_driver_version`:**
        * **Functionality:** It takes a CUDA Toolkit version as input and returns the minimum required NVIDIA driver version for Windows and Linux. It uses a lookup table.
        * **Relevance to Reverse Engineering:** While not directly involved in runtime reverse engineering, it's crucial for *setting up the development environment* for Frida, which *is* a reverse engineering tool. Incorrect drivers can cause Frida to malfunction.
        * **Low-Level/Kernel Relevance:** Driver versions are very low-level and directly interact with the operating system kernel and hardware.
        * **Logic/Assumptions:** Assumes the provided CUDA version string is valid. The output is dependent on the hardcoded table and the host OS.
        * **User Errors:** Providing an incorrect or non-string CUDA version.
        * **User Path:**  A developer building Frida needs to ensure they have the correct CUDA Toolkit and drivers. Meson, during the build, might call this function to verify compatibility or set build flags.

    * **`nvcc_arch_flags` and `nvcc_arch_readable`:**
        * **Functionality:**  These functions generate flags for the `nvcc` compiler related to GPU architecture targets. `nvcc_arch_flags` produces compiler flags, while `nvcc_arch_readable` generates human-readable architecture names. They share the core logic in `_nvcc_arch_flags`.
        * **Relevance to Reverse Engineering:** Frida often needs to execute code on the target device's GPU. Specifying the correct GPU architectures ensures the compiled CUDA code runs efficiently on the intended hardware. Reverse engineers analyzing GPU-accelerated applications need to understand these architecture differences.
        * **Low-Level/Kernel Relevance:** GPU architectures are hardware-level details. The compiler flags directly instruct the compiler on how to generate machine code for specific GPU instruction sets.
        * **Logic/Assumptions:**  The code has a complex logic based on CUDA Toolkit versions to determine supported architectures. It handles special keywords like "All", "Common", and "Auto".
        * **User Errors:**
            * Providing invalid architecture names.
            * Using "All", "Common", or "Auto" alongside specific architectures.
            * Incorrectly specifying the CUDA compiler or version.
        * **User Path:**  When configuring the Frida build with Meson, developers can specify the target CUDA architectures. Meson uses this module to translate those specifications into compiler flags.

    * **`_nvcc_arch_flags` (Internal Logic):**
        * **Functionality:** This is the core logic for determining the `-gencode` flags for `nvcc`. It has a large conditional block based on the CUDA Toolkit version to define supported GPU architectures.
        * **Key Observations:**
            * It maintains lists of known, common, and all architectures.
            * It handles the evolution of CUDA architectures over different toolkit versions.
            * It generates both "compute" (PTX) and "sm" (SASS) code.
        * **Relevance:**  Understanding how CUDA code is compiled for different GPU architectures is essential for reverse engineering GPU-accelerated software.

5. **Connect to Frida:** Emphasize that this module is *part of Frida's build process*. It ensures that when Frida components need to compile CUDA code (e.g., for GPU-based instrumentation or analysis), the compilation is done correctly for the target hardware.

6. **Structure the Explanation:** Organize the findings into logical sections:
    * Introduction and Purpose
    * Functionality Breakdown (for each method)
    * Relationship to Reverse Engineering
    * Relationship to Low-Level/Kernel/Framework Knowledge
    * Logical Reasoning (with examples)
    * User Errors (with examples)
    * Debugging Clues (User Path)

7. **Refine and Elaborate:**  Go back through each section and add details, examples, and explanations to make the information clear and comprehensive. For instance, explain what PTX and SASS are, and why targeting specific architectures matters. Provide concrete examples of user errors.

8. **Review and Verify:**  Read through the entire explanation to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For example, initially, I might have just said it generates compiler flags. Refining this involves explaining *what kind* of flags and *why* they are important.

This iterative process of analyzing the code, identifying its components, understanding their function, and then connecting it back to the broader context of Frida and reverse engineering leads to a comprehensive explanation like the example provided in the prompt.
这是一个名为 `cuda.py` 的 Python 源代码文件，位于 Frida 动态 instrumentation 工具的 `frida/releng/meson/mesonbuild/modules/` 目录下。这个文件是 Meson 构建系统的一个模块，专门用于处理与 CUDA 相关的构建任务。

**功能列举:**

该模块的主要功能是帮助在 Frida 的构建过程中处理 CUDA 代码的编译，具体包括：

1. **确定最低驱动版本 (`min_driver_version`):**  根据提供的 CUDA Toolkit 版本，查询并返回在 Windows 和 Linux 平台上所需的最低 NVIDIA 驱动程序版本。这有助于确保 Frida 构建出的组件能够在使用 CUDA 的系统上正常运行。

2. **生成 NVCC 架构标志 (`nvcc_arch_flags`):**  根据指定的 CUDA Toolkit 版本和目标架构列表，生成传递给 NVIDIA CUDA 编译器 `nvcc` 的命令行标志，用于指定编译出的代码应在哪些 GPU 架构上运行。

3. **生成可读的 NVCC 架构名称 (`nvcc_arch_readable`):**  与 `nvcc_arch_flags` 类似，但返回的是人类可读的 GPU 架构名称，而不是编译器标志。这有助于用户理解所选择的架构。

**与逆向方法的关系及举例说明:**

虽然这个模块本身不是直接进行逆向操作的工具，但它为构建 Frida 提供了支持，而 Frida 是一个强大的逆向工程工具。

* **指定目标 GPU 架构进行逆向分析:**  在逆向分析一个使用 CUDA 加速的应用程序时，理解程序在哪些 GPU 架构上运行是至关重要的。`nvcc_arch_flags` 和 `nvcc_arch_readable` 可以帮助 Frida 开发者构建出针对特定 GPU 架构优化的 Frida 组件。例如，如果逆向工程师知道目标应用程序主要在 Maxwell 架构的 GPU 上运行，他们可以配置 Frida 的构建系统，使用这个模块生成针对 Maxwell 架构的编译标志，以提高 Frida 在该环境下的效率。

* **理解 CUDA 版本与驱动的依赖关系:**  `min_driver_version` 功能可以帮助逆向工程师了解特定 CUDA Toolkit 版本所需的最低驱动程序版本。这对于复现目标应用程序的运行环境或排查 Frida 在特定环境下的问题很有帮助。例如，如果逆向工程师发现 Frida 在某个使用了 CUDA 11.0 的系统上运行不稳定，他们可以使用 `min_driver_version` 查询 CUDA 11.0 的最低驱动版本，并检查目标系统是否满足要求。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **二进制底层 (GPU 架构):**  `nvcc_arch_flags` 涉及到 GPU 的底层架构，例如 Fermi、Kepler、Maxwell、Pascal 等。不同的 GPU 架构支持不同的指令集和特性。这个模块需要根据 CUDA Toolkit 版本和用户指定的架构，生成正确的 `-gencode` 标志，告诉 `nvcc` 编译器生成针对特定架构的机器码（SASS）和中间表示（PTX）。例如，`-gencode arch=compute_70,code=sm_70` 指示编译器生成支持 Volta 架构 (SM 7.0) 的代码。

* **Linux 驱动:** `min_driver_version` 函数中包含了 Linux 平台所需的最低驱动版本信息。驱动程序是连接操作系统内核和硬件的关键组件。CUDA 应用程序的运行依赖于正确的 NVIDIA 驱动程序。例如，如果 CUDA Toolkit 版本是 11.8.0，该模块会查到 Linux 平台所需的最低驱动版本是 `520.61.05`。

* **Android (间接):**  虽然代码本身没有直接提到 Android 内核或框架，但 Frida 可以用于 Android 平台的逆向工程。Frida 在 Android 上的运行也可能涉及到 CUDA 代码的编译（例如，如果 Frida 的某些功能使用了 GPU 加速）。因此，这个模块生成的 CUDA 编译标志也可能影响 Frida 在 Android 设备上的行为。例如，开发者可能需要针对 Android 设备中常见的 GPU 架构进行编译。

**逻辑推理 (假设输入与输出):**

假设调用 `min_driver_version` 函数并传入 CUDA Toolkit 版本字符串 "11.5.0":

* **假设输入:** `cuda_version = "11.5.0"`
* **预期输出 (Linux):** `"495.29.05"`
* **预期输出 (Windows):** `"496.04"`

假设调用 `nvcc_arch_flags` 函数，指定 CUDA Toolkit 版本为 "11.0" 且目标架构为 "Auto"（自动检测）：

* **假设输入:** `cuda_version = "11.0"`, `arch_list = ["Auto"]`, `detected` 根据环境可能为空或者包含检测到的架构信息。
* **逻辑推理:**
    * 由于 CUDA 版本 >= 11.0，最低支持的架构是 3.5。
    * 如果 `detected` 为空，则会使用 common 架构。
    * 根据 CUDA 11.0 的 common 架构定义，会包含 '8.0'。
    * 函数会生成针对 SM 8.0 的编译标志。
* **预期输出 (部分):** `['-gencode', 'arch=compute_80,code=sm_80']`

**涉及用户或者编程常见的使用错误及举例说明:**

1. **`min_driver_version` 参数错误:**
   * **错误:** 调用 `min_driver_version()` 时没有提供任何参数，或者提供了多个参数。
   * **后果:** 抛出 `InvalidArguments` 异常，提示用户需要一个 CUDA Toolkit 版本字符串作为参数。
   * **示例代码 (meson.build):**
     ```meson
     # 错误用法
     min_driver = cuda_mod.min_driver_version()

     # 错误用法
     min_driver = cuda_mod.min_driver_version('11.0', 'extra_arg')

     # 正确用法
     min_driver = cuda_mod.min_driver_version('11.0')
     ```

2. **`nvcc_arch_flags` 或 `nvcc_arch_readable` 架构参数错误:**
   * **错误:** 在 `arch_list` 中同时使用了特殊架构关键字（如 "All", "Common", "Auto"）和其他具体的架构名称。
   * **后果:** 抛出 `InvalidArguments` 异常，提示用户特殊架构关键字必须单独作为位置参数出现。
   * **示例代码 (meson.build):**
     ```meson
     # 错误用法
     arch_flags = cuda_mod.nvcc_arch_flags(cuda_compiler, 'Auto', 'sm_50')

     # 正确用法
     arch_flags_auto = cuda_mod.nvcc_arch_flags(cuda_compiler, 'Auto')
     arch_flags_specific = cuda_mod.nvcc_arch_flags(cuda_compiler, 'sm_50')
     ```

3. **`nvcc_arch_flags` 或 `nvcc_arch_readable` 的 `detected` 关键字参数错误:**
   * **错误:**  在 `detected` 列表中同时使用了特殊架构关键字和其他具体的架构名称。
   * **后果:** 抛出 `InvalidArguments` 异常，提示用户特殊架构关键字必须单独作为位置参数出现。
   * **示例代码 (meson.build):**
     ```meson
     # 错误用法
     arch_flags = cuda_mod.nvcc_arch_flags(cuda_compiler, detected: ['Auto', 'sm_50'])

     # 正确用法
     arch_flags_auto = cuda_mod.nvcc_arch_flags(cuda_compiler, detected: ['Auto'])
     arch_flags_specific = cuda_mod.nvcc_arch_flags(cuda_compiler, detected: ['sm_50'])
     ```

4. **提供未知的 CUDA 架构名称:**
   * **错误:** 在 `nvcc_arch_flags` 或 `nvcc_arch_readable` 中提供了 CUDA Toolkit 版本不支持或不存在的架构名称。
   * **后果:** 抛出 `InvalidArguments` 异常，提示用户架构名称未知。
   * **示例代码 (meson.build):**
     ```meson
     # 假设 'sm_99' 是一个不存在的架构
     arch_flags = cuda_mod.nvcc_arch_flags(cuda_compiler, 'sm_99')
     ```

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **配置 Frida 的构建环境:** 用户首先需要配置 Frida 的构建环境，这通常涉及到安装 Meson、Python 以及必要的依赖库。

2. **运行 Meson 配置:**  用户在 Frida 的源代码目录下运行 `meson setup build` 命令（或其他类似的 Meson 命令）来配置构建系统。

3. **Meson 执行构建脚本:** Meson 会读取 `meson.build` 文件，其中会调用各个模块的功能。当 Meson 处理涉及到 CUDA 的组件时，就会加载 `frida/releng/meson/mesonbuild/modules/cuda.py` 这个模块。

4. **调用 CUDA 模块的方法:**  在 `meson.build` 文件中，可能会有类似以下的调用：
   ```meson
   cuda_mod = import('cuda')
   min_driver = cuda_mod.min_driver_version('12.0')
   cuda_flags = cuda_mod.nvcc_arch_flags(cuda_compiler, 'Auto')
   ```
   这些调用会执行 `cuda.py` 模块中定义的方法。

5. **在调试中定位到此文件:** 如果在 Frida 的构建过程中遇到与 CUDA 相关的错误，例如编译器找不到指定的架构，或者提示驱动版本不兼容，开发者可能会：
   * **查看 Meson 的构建日志:**  日志中会显示 Meson 执行的命令和输出，可能会包含与 CUDA 编译相关的错误信息。
   * **检查 `meson.build` 文件:** 查看 Frida 的构建脚本，了解 CUDA 模块是如何被调用的，以及传递了哪些参数。
   * **单步调试 Meson 脚本 (如果需要):**  Meson 提供了一些调试工具，可以帮助开发者逐步执行构建脚本，查看变量的值和函数的调用过程。通过单步调试，开发者可以追踪到 `cuda.py` 模块的执行，并查看其输入和输出，从而定位问题。
   * **查看 Frida 的源代码:** 如果错误发生在 CUDA 模块内部，开发者可能需要查看 `cuda.py` 的源代码，分析其逻辑，并找出错误的原因。例如，检查 `_nvcc_arch_flags` 函数中对于特定 CUDA 版本和架构的处理是否正确。

总而言之，`frida/releng/meson/mesonbuild/modules/cuda.py` 是 Frida 构建系统中一个关键的模块，负责处理 CUDA 相关的构建配置，确保 Frida 能够正确地编译和运行在使用 CUDA 的目标系统上。理解其功能和使用方式对于 Frida 的开发者和需要构建自定义 Frida 版本的用户来说至关重要。

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/modules/cuda.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 The Meson development team

from __future__ import annotations

import re
import typing as T

from ..mesonlib import listify, version_compare
from ..compilers.cuda import CudaCompiler
from ..interpreter.type_checking import NoneType

from . import NewExtensionModule, ModuleInfo

from ..interpreterbase import (
    ContainerTypeInfo, InvalidArguments, KwargInfo, noKwargs, typed_kwargs, typed_pos_args,
)

if T.TYPE_CHECKING:
    from typing_extensions import TypedDict

    from . import ModuleState
    from ..interpreter import Interpreter
    from ..interpreterbase import TYPE_var

    class ArchFlagsKwargs(TypedDict):
        detected: T.Optional[T.List[str]]

    AutoArch = T.Union[str, T.List[str]]


DETECTED_KW: KwargInfo[T.Union[None, T.List[str]]] = KwargInfo('detected', (ContainerTypeInfo(list, str), NoneType), listify=True)

class CudaModule(NewExtensionModule):

    INFO = ModuleInfo('CUDA', '0.50.0', unstable=True)

    def __init__(self, interp: Interpreter):
        super().__init__()
        self.methods.update({
            "min_driver_version": self.min_driver_version,
            "nvcc_arch_flags":    self.nvcc_arch_flags,
            "nvcc_arch_readable": self.nvcc_arch_readable,
        })

    @noKwargs
    def min_driver_version(self, state: 'ModuleState',
                           args: T.List[TYPE_var],
                           kwargs: T.Dict[str, T.Any]) -> str:
        argerror = InvalidArguments('min_driver_version must have exactly one positional argument: ' +
                                    'a CUDA Toolkit version string. Beware that, since CUDA 11.0, ' +
                                    'the CUDA Toolkit\'s components (including NVCC) are versioned ' +
                                    'independently from each other (and the CUDA Toolkit as a whole).')

        if len(args) != 1 or not isinstance(args[0], str):
            raise argerror

        cuda_version = args[0]
        driver_version_table = [
            {'cuda_version': '>=12.0.0',   'windows': '527.41', 'linux': '525.60.13'},
            {'cuda_version': '>=11.8.0',   'windows': '522.06', 'linux': '520.61.05'},
            {'cuda_version': '>=11.7.1',   'windows': '516.31', 'linux': '515.48.07'},
            {'cuda_version': '>=11.7.0',   'windows': '516.01', 'linux': '515.43.04'},
            {'cuda_version': '>=11.6.1',   'windows': '511.65', 'linux': '510.47.03'},
            {'cuda_version': '>=11.6.0',   'windows': '511.23', 'linux': '510.39.01'},
            {'cuda_version': '>=11.5.1',   'windows': '496.13', 'linux': '495.29.05'},
            {'cuda_version': '>=11.5.0',   'windows': '496.04', 'linux': '495.29.05'},
            {'cuda_version': '>=11.4.3',   'windows': '472.50', 'linux': '470.82.01'},
            {'cuda_version': '>=11.4.1',   'windows': '471.41', 'linux': '470.57.02'},
            {'cuda_version': '>=11.4.0',   'windows': '471.11', 'linux': '470.42.01'},
            {'cuda_version': '>=11.3.0',   'windows': '465.89', 'linux': '465.19.01'},
            {'cuda_version': '>=11.2.2',   'windows': '461.33', 'linux': '460.32.03'},
            {'cuda_version': '>=11.2.1',   'windows': '461.09', 'linux': '460.32.03'},
            {'cuda_version': '>=11.2.0',   'windows': '460.82', 'linux': '460.27.03'},
            {'cuda_version': '>=11.1.1',   'windows': '456.81', 'linux': '455.32'},
            {'cuda_version': '>=11.1.0',   'windows': '456.38', 'linux': '455.23'},
            {'cuda_version': '>=11.0.3',   'windows': '451.82', 'linux': '450.51.06'},
            {'cuda_version': '>=11.0.2',   'windows': '451.48', 'linux': '450.51.05'},
            {'cuda_version': '>=11.0.1',   'windows': '451.22', 'linux': '450.36.06'},
            {'cuda_version': '>=10.2.89',  'windows': '441.22', 'linux': '440.33'},
            {'cuda_version': '>=10.1.105', 'windows': '418.96', 'linux': '418.39'},
            {'cuda_version': '>=10.0.130', 'windows': '411.31', 'linux': '410.48'},
            {'cuda_version': '>=9.2.148',  'windows': '398.26', 'linux': '396.37'},
            {'cuda_version': '>=9.2.88',   'windows': '397.44', 'linux': '396.26'},
            {'cuda_version': '>=9.1.85',   'windows': '391.29', 'linux': '390.46'},
            {'cuda_version': '>=9.0.76',   'windows': '385.54', 'linux': '384.81'},
            {'cuda_version': '>=8.0.61',   'windows': '376.51', 'linux': '375.26'},
            {'cuda_version': '>=8.0.44',   'windows': '369.30', 'linux': '367.48'},
            {'cuda_version': '>=7.5.16',   'windows': '353.66', 'linux': '352.31'},
            {'cuda_version': '>=7.0.28',   'windows': '347.62', 'linux': '346.46'},
        ]

        driver_version = 'unknown'
        for d in driver_version_table:
            if version_compare(cuda_version, d['cuda_version']):
                driver_version = d.get(state.environment.machines.host.system, d['linux'])
                break

        return driver_version

    @typed_pos_args('cuda.nvcc_arch_flags', (str, CudaCompiler), varargs=str)
    @typed_kwargs('cuda.nvcc_arch_flags', DETECTED_KW)
    def nvcc_arch_flags(self, state: 'ModuleState',
                        args: T.Tuple[T.Union[CudaCompiler, str], T.List[str]],
                        kwargs: ArchFlagsKwargs) -> T.List[str]:
        nvcc_arch_args = self._validate_nvcc_arch_args(args, kwargs)
        ret = self._nvcc_arch_flags(*nvcc_arch_args)[0]
        return ret

    @typed_pos_args('cuda.nvcc_arch_readable', (str, CudaCompiler), varargs=str)
    @typed_kwargs('cuda.nvcc_arch_readable', DETECTED_KW)
    def nvcc_arch_readable(self, state: 'ModuleState',
                           args: T.Tuple[T.Union[CudaCompiler, str], T.List[str]],
                           kwargs: ArchFlagsKwargs) -> T.List[str]:
        nvcc_arch_args = self._validate_nvcc_arch_args(args, kwargs)
        ret = self._nvcc_arch_flags(*nvcc_arch_args)[1]
        return ret

    @staticmethod
    def _break_arch_string(s: str) -> T.List[str]:
        s = re.sub('[ \t\r\n,;]+', ';', s)
        return s.strip(';').split(';')

    @staticmethod
    def _detected_cc_from_compiler(c: T.Union[str, CudaCompiler]) -> T.List[str]:
        if isinstance(c, CudaCompiler):
            return [c.detected_cc]
        return []

    def _validate_nvcc_arch_args(self, args: T.Tuple[T.Union[str, CudaCompiler], T.List[str]],
                                 kwargs: ArchFlagsKwargs) -> T.Tuple[str, AutoArch, T.List[str]]:

        compiler = args[0]
        if isinstance(compiler, CudaCompiler):
            cuda_version = compiler.version
        else:
            cuda_version = compiler

        arch_list: AutoArch = args[1]
        arch_list = listify([self._break_arch_string(a) for a in arch_list])
        if len(arch_list) > 1 and not set(arch_list).isdisjoint({'All', 'Common', 'Auto'}):
            raise InvalidArguments('''The special architectures 'All', 'Common' and 'Auto' must appear alone, as a positional argument!''')
        arch_list = arch_list[0] if len(arch_list) == 1 else arch_list

        detected = kwargs['detected'] if kwargs['detected'] is not None else self._detected_cc_from_compiler(compiler)
        detected = [x for a in detected for x in self._break_arch_string(a)]
        if not set(detected).isdisjoint({'All', 'Common', 'Auto'}):
            raise InvalidArguments('''The special architectures 'All', 'Common' and 'Auto' must appear alone, as a positional argument!''')

        return cuda_version, arch_list, detected

    def _filter_cuda_arch_list(self, cuda_arch_list: T.List[str], lo: str, hi: T.Optional[str], saturate: str) -> T.List[str]:
        """
        Filter CUDA arch list (no codenames) for >= low and < hi architecture
        bounds, and deduplicate.
        Architectures >= hi are replaced with saturate.
        """

        filtered_cuda_arch_list = []
        for arch in cuda_arch_list:
            if arch:
                if lo and version_compare(arch, '<' + lo):
                    continue
                if hi and version_compare(arch, '>=' + hi):
                    arch = saturate
                if arch not in filtered_cuda_arch_list:
                    filtered_cuda_arch_list.append(arch)
        return filtered_cuda_arch_list

    def _nvcc_arch_flags(self, cuda_version: str, cuda_arch_list: AutoArch, detected: T.List[str]) -> T.Tuple[T.List[str], T.List[str]]:
        """
        Using the CUDA Toolkit version and the target architectures, compute
        the NVCC architecture flags.
        """

        # Replicates much of the logic of
        #     https://github.com/Kitware/CMake/blob/master/Modules/FindCUDA/select_compute_arch.cmake
        # except that a bug with cuda_arch_list="All" is worked around by
        # tracking both lower and upper limits on GPU architectures.

        cuda_known_gpu_architectures   = ['Fermi', 'Kepler', 'Maxwell']  # noqa: E221
        cuda_common_gpu_architectures  = ['3.0', '3.5', '5.0']           # noqa: E221
        cuda_hi_limit_gpu_architecture = None                            # noqa: E221
        cuda_lo_limit_gpu_architecture = '2.0'                           # noqa: E221
        cuda_all_gpu_architectures     = ['3.0', '3.2', '3.5', '5.0']    # noqa: E221

        if version_compare(cuda_version, '<7.0'):
            cuda_hi_limit_gpu_architecture = '5.2'

        if version_compare(cuda_version, '>=7.0'):
            cuda_known_gpu_architectures  += ['Kepler+Tegra', 'Kepler+Tesla', 'Maxwell+Tegra']  # noqa: E221
            cuda_common_gpu_architectures += ['5.2']                                            # noqa: E221

            if version_compare(cuda_version, '<8.0'):
                cuda_common_gpu_architectures += ['5.2+PTX']  # noqa: E221
                cuda_hi_limit_gpu_architecture = '6.0'        # noqa: E221

        if version_compare(cuda_version, '>=8.0'):
            cuda_known_gpu_architectures  += ['Pascal', 'Pascal+Tegra']  # noqa: E221
            cuda_common_gpu_architectures += ['6.0', '6.1']              # noqa: E221
            cuda_all_gpu_architectures    += ['6.0', '6.1', '6.2']       # noqa: E221

            if version_compare(cuda_version, '<9.0'):
                cuda_common_gpu_architectures += ['6.1+PTX']  # noqa: E221
                cuda_hi_limit_gpu_architecture = '7.0'        # noqa: E221

        if version_compare(cuda_version, '>=9.0'):
            cuda_known_gpu_architectures  += ['Volta', 'Xavier'] # noqa: E221
            cuda_common_gpu_architectures += ['7.0']             # noqa: E221
            cuda_all_gpu_architectures    += ['7.0', '7.2']      # noqa: E221
            # https://docs.nvidia.com/cuda/archive/9.0/cuda-toolkit-release-notes/index.html#unsupported-features
            cuda_lo_limit_gpu_architecture = '3.0'               # noqa: E221

            if version_compare(cuda_version, '<10.0'):
                cuda_common_gpu_architectures += ['7.2+PTX']  # noqa: E221
                cuda_hi_limit_gpu_architecture = '8.0'        # noqa: E221

        if version_compare(cuda_version, '>=10.0'):
            cuda_known_gpu_architectures  += ['Turing'] # noqa: E221
            cuda_common_gpu_architectures += ['7.5']    # noqa: E221
            cuda_all_gpu_architectures    += ['7.5']    # noqa: E221

            if version_compare(cuda_version, '<11.0'):
                cuda_common_gpu_architectures += ['7.5+PTX']  # noqa: E221
                cuda_hi_limit_gpu_architecture = '8.0'        # noqa: E221

        # need to account for the fact that Ampere is commonly assumed to include
        # SM8.0 and SM8.6 even though CUDA 11.0 doesn't support SM8.6
        cuda_ampere_bin = ['8.0']
        cuda_ampere_ptx = ['8.0']
        if version_compare(cuda_version, '>=11.0'):
            cuda_known_gpu_architectures  += ['Ampere'] # noqa: E221
            cuda_common_gpu_architectures += ['8.0']    # noqa: E221
            cuda_all_gpu_architectures    += ['8.0']    # noqa: E221
            # https://docs.nvidia.com/cuda/archive/11.0/cuda-toolkit-release-notes/index.html#deprecated-features
            cuda_lo_limit_gpu_architecture = '3.5'      # noqa: E221

            if version_compare(cuda_version, '<11.1'):
                cuda_common_gpu_architectures += ['8.0+PTX']  # noqa: E221
                cuda_hi_limit_gpu_architecture = '8.6'        # noqa: E221

        if version_compare(cuda_version, '>=11.1'):
            cuda_ampere_bin += ['8.6'] # noqa: E221
            cuda_ampere_ptx  = ['8.6'] # noqa: E221

            cuda_common_gpu_architectures += ['8.6']             # noqa: E221
            cuda_all_gpu_architectures    += ['8.6']             # noqa: E221

            if version_compare(cuda_version, '<11.8'):
                cuda_common_gpu_architectures += ['8.6+PTX']  # noqa: E221
                cuda_hi_limit_gpu_architecture = '8.7'        # noqa: E221

        if version_compare(cuda_version, '>=11.8'):
            cuda_known_gpu_architectures  += ['Orin', 'Lovelace', 'Hopper']  # noqa: E221
            cuda_common_gpu_architectures += ['8.9', '9.0', '9.0+PTX']       # noqa: E221
            cuda_all_gpu_architectures    += ['8.7', '8.9', '9.0']           # noqa: E221

            if version_compare(cuda_version, '<12'):
                cuda_hi_limit_gpu_architecture = '9.1'        # noqa: E221

        if version_compare(cuda_version, '>=12.0'):
            # https://docs.nvidia.com/cuda/cuda-toolkit-release-notes/index.html#deprecated-features (Current)
            # https://docs.nvidia.com/cuda/archive/12.0/cuda-toolkit-release-notes/index.html#deprecated-features (Eventual?)
            cuda_lo_limit_gpu_architecture = '5.0'            # noqa: E221

            if version_compare(cuda_version, '<13'):
                cuda_hi_limit_gpu_architecture = '10.0'       # noqa: E221

        if not cuda_arch_list:
            cuda_arch_list = 'Auto'

        if   cuda_arch_list == 'All':     # noqa: E271
            cuda_arch_list = cuda_known_gpu_architectures
        elif cuda_arch_list == 'Common':  # noqa: E271
            cuda_arch_list = cuda_common_gpu_architectures
        elif cuda_arch_list == 'Auto':    # noqa: E271
            if detected:
                if isinstance(detected, list):
                    cuda_arch_list = detected
                else:
                    cuda_arch_list = self._break_arch_string(detected)
                cuda_arch_list = self._filter_cuda_arch_list(cuda_arch_list,
                                                             cuda_lo_limit_gpu_architecture,
                                                             cuda_hi_limit_gpu_architecture,
                                                             cuda_common_gpu_architectures[-1])
            else:
                cuda_arch_list = cuda_common_gpu_architectures
        elif isinstance(cuda_arch_list, str):
            cuda_arch_list = self._break_arch_string(cuda_arch_list)

        cuda_arch_list = sorted(x for x in set(cuda_arch_list) if x)

        cuda_arch_bin: T.List[str] = []
        cuda_arch_ptx: T.List[str] = []
        for arch_name in cuda_arch_list:
            arch_bin: T.Optional[T.List[str]]
            arch_ptx: T.Optional[T.List[str]]
            add_ptx = arch_name.endswith('+PTX')
            if add_ptx:
                arch_name = arch_name[:-len('+PTX')]

            if re.fullmatch('[0-9]+\\.[0-9](\\([0-9]+\\.[0-9]\\))?', arch_name):
                arch_bin, arch_ptx = [arch_name], [arch_name]
            else:
                arch_bin, arch_ptx = {
                    'Fermi':         (['2.0', '2.1(2.0)'], []),
                    'Kepler+Tegra':  (['3.2'],             []),
                    'Kepler+Tesla':  (['3.7'],             []),
                    'Kepler':        (['3.0', '3.5'],      ['3.5']),
                    'Maxwell+Tegra': (['5.3'],             []),
                    'Maxwell':       (['5.0', '5.2'],      ['5.2']),
                    'Pascal':        (['6.0', '6.1'],      ['6.1']),
                    'Pascal+Tegra':  (['6.2'],             []),
                    'Volta':         (['7.0'],             ['7.0']),
                    'Xavier':        (['7.2'],             []),
                    'Turing':        (['7.5'],             ['7.5']),
                    'Ampere':        (cuda_ampere_bin,     cuda_ampere_ptx),
                    'Orin':          (['8.7'],             []),
                    'Lovelace':      (['8.9'],             ['8.9']),
                    'Hopper':        (['9.0'],             ['9.0']),
                }.get(arch_name, (None, None))

            if arch_bin is None:
                raise InvalidArguments(f'Unknown CUDA Architecture Name {arch_name}!')

            cuda_arch_bin += arch_bin

            if add_ptx:
                if not arch_ptx:
                    arch_ptx = arch_bin
                cuda_arch_ptx += arch_ptx

        cuda_arch_bin = sorted(set(cuda_arch_bin))
        cuda_arch_ptx = sorted(set(cuda_arch_ptx))

        nvcc_flags = []
        nvcc_archs_readable = []

        for arch in cuda_arch_bin:
            arch, codev = re.fullmatch(
                '([0-9]+\\.[0-9])(?:\\(([0-9]+\\.[0-9])\\))?', arch).groups()

            if version_compare(arch, '<' + cuda_lo_limit_gpu_architecture):
                continue
            if cuda_hi_limit_gpu_architecture and version_compare(arch, '>=' + cuda_hi_limit_gpu_architecture):
                continue

            if codev:
                arch = arch.replace('.', '')
                codev = codev.replace('.', '')
                nvcc_flags += ['-gencode', 'arch=compute_' + codev + ',code=sm_' + arch]
                nvcc_archs_readable += ['sm_' + arch]
            else:
                arch = arch.replace('.', '')
                nvcc_flags += ['-gencode', 'arch=compute_' + arch + ',code=sm_' + arch]
                nvcc_archs_readable += ['sm_' + arch]

        for arch in cuda_arch_ptx:
            arch, codev = re.fullmatch(
                '([0-9]+\\.[0-9])(?:\\(([0-9]+\\.[0-9])\\))?', arch).groups()

            if codev:
                arch = codev

            if version_compare(arch, '<' + cuda_lo_limit_gpu_architecture):
                continue
            if cuda_hi_limit_gpu_architecture and version_compare(arch, '>=' + cuda_hi_limit_gpu_architecture):
                continue

            arch = arch.replace('.', '')
            nvcc_flags += ['-gencode', 'arch=compute_' + arch + ',code=compute_' + arch]
            nvcc_archs_readable += ['compute_' + arch]

        return nvcc_flags, nvcc_archs_readable

def initialize(interp: Interpreter) -> CudaModule:
    return CudaModule(interp)

"""

```