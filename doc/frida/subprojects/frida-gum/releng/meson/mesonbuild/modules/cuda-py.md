Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding and Purpose:**

The first step is to recognize the file path `frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/cuda.py`. This immediately suggests several things:

* **Frida:** This is related to the Frida dynamic instrumentation toolkit. This is the most crucial piece of context.
* **Subprojects and `frida-gum`:** Frida is likely organized into sub-components. `frida-gum` is probably the core instrumentation engine.
* **`releng/meson/mesonbuild/modules`:**  This path indicates this file is part of Frida's build system, specifically using the Meson build tool. The `modules` directory strongly implies this code provides extra functionality or extensions to the build process related to CUDA.
* **`cuda.py`:** The filename directly points to functionality related to NVIDIA's CUDA platform for GPU computing.

Therefore, the core purpose of this file is to provide Meson build system integration specifically for projects that use CUDA within the Frida framework.

**2. Dissecting the Code - Function by Function:**

The next step is to go through the code, function by function, and understand what each part does:

* **Imports:**  Standard Python imports are a good starting point. `re` for regular expressions, `typing` for type hints, and imports from `mesonlib`, `compilers.cuda`, `interpreter`, and `interpreterbase` provide clues about the dependencies and context within the Meson build system. The `TypedDict` import reinforces the type hinting.

* **`CudaModule` Class:** This is the main component. The `INFO` attribute tells us the module's name and version. The `__init__` method registers the module's methods.

* **`min_driver_version`:** This function takes a CUDA Toolkit version string as input and returns the minimum recommended NVIDIA driver version for that toolkit. It uses a lookup table. The comment about independent versioning of CUDA components is important context.

* **`nvcc_arch_flags`:** This function appears to generate the necessary flags for the `nvcc` compiler (the CUDA compiler) to target specific GPU architectures. It takes either a CUDA version string or a `CudaCompiler` object, and a list of target architectures. It also takes a `detected` keyword argument.

* **`nvcc_arch_readable`:** This function seems to do something similar to `nvcc_arch_flags` but returns a more human-readable representation of the target architectures.

* **`_break_arch_string`:** This utility function splits a string of architectures into a list.

* **`_detected_cc_from_compiler`:** This helper extracts the detected compute capability from a `CudaCompiler` object.

* **`_validate_nvcc_arch_args`:** This function validates the arguments passed to `nvcc_arch_flags` and `nvcc_arch_readable`, ensuring they are in the correct format and handle special keywords like "All", "Common", and "Auto".

* **`_filter_cuda_arch_list`:** This function filters a list of CUDA architectures based on minimum and maximum versions and handles a "saturate" case.

* **`_nvcc_arch_flags`:** This is the core logic for determining the `nvcc` flags. It has a large block of conditional logic based on the CUDA Toolkit version to determine supported architectures and generate the correct `-gencode` flags. The comments referencing CMake are important for understanding the origin of the logic.

* **`initialize`:** This function is the entry point for the Meson module.

**3. Connecting to the Prompts:**

Now, with an understanding of the code, the next step is to relate the functionality to the specific aspects requested in the prompt:

* **Functionality:**  Summarize the purpose of each key function.

* **Relationship to Reverse Engineering:** Consider how generating `nvcc` flags for specific architectures relates to targeting specific GPU features, which can be relevant in reverse engineering CUDA code. Instrumentation itself is a core reverse engineering technique, and CUDA code is a target.

* **Binary/Low-Level/Kernel/Framework:** Think about how CUDA interacts with the GPU hardware (binary/low-level), how Frida might interact with the operating system (Linux/Android kernel), and how it all fits within a larger software framework.

* **Logic Reasoning (Input/Output):**  Pick a function like `min_driver_version` or `nvcc_arch_flags` and create concrete examples of inputs and the expected outputs based on the code's logic.

* **User/Programming Errors:** Identify common mistakes a user might make when using this module, such as providing incorrect version strings or architecture names.

* **User Path to Reach the Code (Debugging):** Imagine a scenario where a user is building a Frida project with CUDA support and encounters an issue. Trace the steps that would lead them to potentially examining this `cuda.py` file for debugging.

**4. Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, using headings and bullet points as provided in the example output. Ensure each point is explained with relevant details and examples. It's important to connect the specific code elements to the broader concepts of Frida, CUDA, and reverse engineering.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe `nvcc_arch_flags` just passes through the arguments.
* **Correction:**  Looking at the `_nvcc_arch_flags` implementation shows a significant amount of logic for determining the correct flags based on CUDA version and target architectures.

* **Initial thought:**  The reverse engineering connection might be weak.
* **Refinement:** Realize that targeting specific GPU architectures for instrumentation or analysis during reverse engineering makes this functionality directly relevant.

By following this systematic process of understanding the code's context, dissecting its functionality, and then relating it to the specific prompt requirements, a comprehensive and accurate answer can be generated.
好的，让我们来分析一下 `frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/cuda.py` 这个文件。

**文件功能概述:**

这个 Python 文件是 Frida (一个动态 instrumentation 工具) 项目中，`frida-gum` 子项目下的一个 Meson 构建系统的模块。它的主要功能是为使用 CUDA（NVIDIA 的并行计算平台和编程模型）的项目提供构建支持。更具体地说，它提供了一些帮助函数，用于处理与 CUDA 编译器 (`nvcc`) 相关的任务，例如：

1. **确定最低要求的 NVIDIA 驱动版本:**  根据提供的 CUDA Toolkit 版本，查找并返回建议的最低 NVIDIA 驱动程序版本。
2. **生成 `nvcc` 架构标志:**  根据指定的 CUDA Toolkit 版本和目标 GPU 架构，生成传递给 `nvcc` 编译器的架构相关的编译标志 (`-gencode arch=compute_XX,code=sm_XX` 等)。
3. **生成 `nvcc` 可读的架构名称:**  为生成的 `nvcc` 架构标志提供更易于理解的名称。

**与逆向方法的关系及举例说明:**

这个模块直接关系到使用 CUDA 的程序进行逆向工程。Frida 可以用于动态地分析和修改正在运行的进程的行为。当目标程序使用 CUDA 进行 GPU 加速计算时，理解和操作 CUDA 的上下文就变得至关重要。

* **确定目标 GPU 架构:**  逆向工程师可能需要知道目标程序在哪些 GPU 架构上运行，以便理解其性能特征、算法实现细节以及潜在的安全漏洞。`nvcc_arch_readable` 函数可以帮助理解编译时指定的目标架构。

* **Hook CUDA API 调用:** Frida 可以 hook 目标程序的 CUDA API 调用，例如 `cudaMalloc`, `cudaMemcpy`, `cudaLaunchKernel` 等。为了正确地解析和理解这些 API 调用的参数和返回值，逆向工程师需要了解目标代码编译时针对的 GPU 架构，因为 CUDA 数据结构和行为可能因架构而异。

* **修改 CUDA Kernel 的行为:**  Frida 允许在运行时修改目标程序的内存。对于 CUDA 程序，这可能涉及到修改 GPU 内存中的数据或甚至修改加载到 GPU 上的 Kernel 代码。要做到这一点，逆向工程师需要理解 Kernel 代码的目标架构，以便注入兼容的代码或修改现有代码。`nvcc_arch_flags` 函数生成的标志指示了编译器如何针对特定架构生成代码，这对于理解编译后的 Kernel 代码很有帮助。

**举例说明:**

假设一个逆向工程师想要分析一个使用了 CUDA 的游戏，并尝试理解其渲染过程。

1. **使用 `nvcc_arch_readable`:**  逆向工程师可能会通过某种方式（例如，查看构建脚本或可执行文件的元数据）获取到游戏编译时使用的 CUDA Toolkit 版本和目标架构信息。然后，他们可以使用 Frida 提供的接口调用这个 Meson 模块的功能，例如：

   ```python
   # 假设已经连接到目标进程
   cuda_module = frida.get_module("CUDA")
   cuda_version = "11.5"  # 从目标程序构建信息中获取
   target_archs = ["Auto"] # 或具体架构列表
   readable_archs = cuda_module.nvcc_arch_readable(cuda_version, target_archs)
   print(f"目标程序 CUDA 编译的目标架构: {readable_archs}")
   ```

   这将输出像 `['sm_75', 'compute_75']` 这样的信息，表明目标程序针对 Turing 架构进行了编译。

2. **使用 `nvcc_arch_flags`:**  如果逆向工程师想要自己编译一些与目标程序 CUDA 代码交互的工具或代码片段，他们可以使用 `nvcc_arch_flags` 来获取正确的编译标志，以确保兼容性：

   ```python
   cuda_module = frida.get_module("CUDA")
   cuda_version = "11.5"
   target_archs = ["7.5"] # 明确指定 Turing 架构
   nvcc_flags = cuda_module.nvcc_arch_flags(cuda_version, target_archs)
   print(f"编译时需要使用的 nvcc 标志: {nvcc_flags}")
   ```

   输出可能类似于 `['-gencode', 'arch=compute_75,code=sm_75', '-gencode', 'arch=compute_75,code=compute_75']`。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **二进制底层:** `nvcc_arch_flags` 函数生成的 `-gencode` 标志直接影响 `nvcc` 编译器生成的目标二进制代码（PTX 或 SASS）。理解这些标志对于分析编译后的 CUDA Kernel 的二进制表示至关重要。不同的 GPU 架构有不同的指令集和特性，这些标志确保生成的代码能在目标硬件上正确运行。

* **Linux:**  `min_driver_version` 函数中的驱动版本信息是针对不同操作系统的，包括 Linux。这反映了 Frida 在 Linux 环境下运行并与 CUDA 交互的需求。Frida 需要检查或建议用户安装合适的 NVIDIA 驱动程序，以便 CUDA 功能正常工作。

* **Android 内核及框架:** 虽然代码本身没有直接提及 Android，但 Frida 广泛应用于 Android 平台的动态分析。如果目标 Android 应用使用了 CUDA（虽然在移动设备上相对较少见），那么这个模块的功能在 Android 上同样适用。Frida 需要与 Android 的图形驱动程序栈和 CUDA 运行时环境交互。

**举例说明:**

* **二进制底层:** 逆向工程师可能会使用反汇编工具（例如 NVIDIA 的 `cuobjdump`）来查看使用特定 `-gencode` 标志编译的 CUDA Kernel 的 SASS 代码，以理解其底层执行细节。

* **Linux:**  在 Linux 系统上运行使用了 CUDA 的 Frida 脚本时，如果提示驱动版本过低，可能是因为 `min_driver_version` 函数返回的值与当前系统安装的驱动版本不匹配。

**逻辑推理、假设输入与输出:**

**`min_driver_version` 函数:**

* **假设输入:** CUDA Toolkit 版本字符串 `"11.7.0"`
* **逻辑推理:** 函数会在 `driver_version_table` 中查找与该版本兼容的最低驱动版本。由于 `"11.7.0"` 匹配 `>=11.7.0`，它会返回对应的 Linux 或 Windows 驱动版本。
* **假设输出 (Linux):** `"515.43.04"`
* **假设输出 (Windows):** `"516.01"`

**`nvcc_arch_flags` 函数:**

* **假设输入:** CUDA Toolkit 版本字符串 `"10.2"`, 目标架构列表 `["Auto"]`,  `detected` 为 `None`。
* **逻辑推理:**
    1. 由于目标架构是 `"Auto"` 且 `detected` 为 `None`，函数会使用 `cuda_common_gpu_architectures` 中定义的通用架构。
    2. 对于 CUDA 10.2，`cuda_common_gpu_architectures` 包括 `['3.0', '3.5', '5.0', '5.2', '6.0', '6.1', '7.0', '7.5']`。
    3. 函数会为这些架构生成对应的 `-gencode` 标志。
* **假设输出:** `['-gencode', 'arch=compute_30,code=sm_30', '-gencode', 'arch=compute_35,code=sm_35', '-gencode', 'arch=compute_50,code=sm_50', '-gencode', 'arch=compute_52,code=sm_52', '-gencode', 'arch=compute_60,code=sm_60', '-gencode', 'arch=compute_61,code=sm_61', '-gencode', 'arch=compute_70,code=sm_70', '-gencode', 'arch=compute_75,code=sm_75', '-gencode', 'arch=compute_75,code=compute_75']`

**涉及用户或编程常见的使用错误及举例说明:**

1. **`min_driver_version` 函数:**
   * **错误输入:** 传递了错误的参数类型，例如整数 `11` 而不是字符串 `"11.0"`。这会导致 `InvalidArguments` 异常。
   * **错误输入:** 传递了多个参数，例如 `cuda_module.min_driver_version("11.0", "some extra info")`。也会导致 `InvalidArguments` 异常。

2. **`nvcc_arch_flags` 和 `nvcc_arch_readable` 函数:**
   * **错误输入:**  提供了无效的 CUDA Toolkit 版本字符串，例如 `"invalid_version"`。虽然代码可能不会立即崩溃，但后续的逻辑可能无法正确处理。
   * **错误输入:**  提供了无法识别的 GPU 架构名称，例如 `["NonExistentGPU"]`。`_nvcc_arch_flags` 函数会抛出 `InvalidArguments` 异常，提示 "Unknown CUDA Architecture Name"。
   * **使用特殊架构关键字不当:** 试图同时指定 "All"、"Common" 或 "Auto" 与其他具体架构，例如 `["Auto", "7.0"]`。这会导致 `InvalidArguments` 异常，因为这些特殊关键字应该单独使用。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设一个 Frida 用户在尝试 hook 一个使用了 CUDA 的应用程序，并且遇到了与 GPU 相关的错误或行为异常。以下是他们可能逐步到达这个 `cuda.py` 文件的过程：

1. **编写 Frida 脚本:** 用户编写了一个 Frida 脚本，尝试 hook CUDA API 调用或修改 GPU 内存。

2. **运行 Frida 脚本并观察错误:**  当运行脚本时，可能会出现以下情况：
   * **驱动版本不兼容:** Frida 可能会抛出异常或警告，提示当前安装的 NVIDIA 驱动程序版本过低，无法支持目标程序使用的 CUDA 版本。这可能会引导用户去检查 Frida 的代码，看它是如何进行版本检查的。
   * **GPU 操作失败或行为异常:**  如果 hook 的逻辑与目标 GPU 架构不兼容，可能会导致程序崩溃或产生意外结果。用户可能会怀疑是他们指定的架构信息不正确。

3. **查阅 Frida 文档或源代码:** 用户可能会查阅 Frida 的官方文档或源代码，寻找与 CUDA 相关的支持和功能。他们可能会发现 `frida.get_module("CUDA")` 可以访问 CUDA 模块的功能。

4. **检查 Meson 构建系统:**  由于 Frida 使用 Meson 构建系统，用户可能会查看 Frida 的构建文件 (`meson.build`)，以了解 CUDA 模块是如何被引入和构建的。这可能会引导他们找到 `subprojects/frida-gum/releng/meson/mesonbuild/modules/cuda.py` 这个文件。

5. **阅读 `cuda.py` 源代码:**  为了调试问题，用户可能会打开 `cuda.py` 文件，查看以下内容：
   * **`min_driver_version` 函数:**  如果遇到驱动版本问题，用户可能会查看这个函数，了解 Frida 是如何判断最低驱动版本的，以及查找 `driver_version_table` 中是否包含了他们使用的 CUDA 版本。
   * **`nvcc_arch_flags` 和 `nvcc_arch_readable` 函数:**  如果怀疑架构信息不正确，用户可能会查看这两个函数，了解 Frida 是如何根据 CUDA 版本和目标架构生成编译标志的。他们可能会检查代码中的逻辑，看看是否有可能存在错误或不匹配的情况。
   * **错误处理逻辑:** 用户可能会关注代码中是否抛出了异常，以及哪些情况下会抛出异常，以便更好地理解他们遇到的错误信息。

总而言之，`frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/cuda.py` 是 Frida 中用于支持 CUDA 构建和提供 CUDA 相关信息的关键模块。它通过提供确定最低驱动版本和生成 `nvcc` 架构标志的功能，帮助 Frida 用户更好地与使用了 CUDA 的目标程序进行交互和逆向分析。理解这个模块的功能对于进行 CUDA 相关的 Frida 开发和调试至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/cuda.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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