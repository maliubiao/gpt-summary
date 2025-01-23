Response:
Let's break down the thought process to analyze this Python code.

**1. Initial Understanding: What is the Goal?**

The first step is to read the docstring at the top. It clearly states this is the `cuda.py` module for the Frida dynamic instrumentation tool, specifically within the `frida-qml` subproject and the `meson` build system. This immediately tells us it's related to compiling CUDA code as part of the Frida build process.

**2. High-Level Functionality Identification:**

Next, skim through the class and method definitions. Keywords like `min_driver_version`, `nvcc_arch_flags`, and `nvcc_arch_readable` stand out. This suggests the module is concerned with:

* **Driver Versioning:** Determining minimum required driver versions for specific CUDA toolkits.
* **Architecture Flags:** Generating appropriate flags for the `nvcc` compiler based on target GPU architectures. This is the core functionality.

**3. Deeper Dive into Each Method:**

* **`min_driver_version`:**  The code clearly uses a lookup table (`driver_version_table`) to map CUDA toolkit versions to minimum driver versions on Windows and Linux. This is straightforward data lookup.

* **`nvcc_arch_flags` and `nvcc_arch_readable`:** These methods seem very similar. They both call `_validate_nvcc_arch_args` and `_nvcc_arch_flags`. This suggests a pattern:
    * **Validation:** `_validate_nvcc_arch_args` handles input processing and error checking.
    * **Core Logic:** `_nvcc_arch_flags` performs the actual computation of the flags.
    * **Output Formatting:**  One returns "flags" suitable for the compiler, the other returns "readable" names (likely for display or logging).

* **`_validate_nvcc_arch_args`:** This method parses the input arguments: the CUDA compiler or version string, and the target architecture list. It also handles special keywords like "All", "Common", and "Auto" for architectures. Error handling for invalid arguments is present.

* **`_nvcc_arch_flags`:** This is the most complex method. It contains a significant amount of logic to determine the correct NVCC flags based on the CUDA toolkit version and the target GPU architectures. Key observations:
    * **Version-Based Logic:**  The code has many `version_compare` calls, indicating different logic depending on the CUDA toolkit version.
    * **Architecture Lists:** It maintains lists of known, common, and all GPU architectures.
    * **Special Architecture Handling:** The "All", "Common", and "Auto" keywords trigger specific logic. "Auto" considers detected architectures.
    * **Flag Generation:**  It generates `-gencode` flags for both binary (`sm_`) and PTX (`compute_`) code.

* **Helper Methods:** `_break_arch_string` and `_detected_cc_from_compiler` perform basic string manipulation and compiler information extraction.

**4. Connecting to Reverse Engineering, Binary/Kernel Knowledge, Logic, and Errors:**

Now, address the specific questions from the prompt:

* **Reverse Engineering:**  The module helps *prepare* CUDA code for execution, which is often a target of reverse engineering. By understanding the architecture flags, a reverse engineer can infer the intended target GPUs and potentially identify performance optimizations or specific hardware features being leveraged. The generated flags themselves are not directly *performing* reverse engineering.

* **Binary/Kernel Knowledge:** The architecture flags (`sm_XX`, `compute_XX`) directly relate to the instruction sets and capabilities of different NVIDIA GPU architectures. This is very much a binary-level concern. The minimum driver version logic touches on OS kernel interactions with the graphics drivers.

* **Logic/Assumptions:** The `_nvcc_arch_flags` method contains significant logical reasoning to map CUDA versions and target architectures to the correct flags. The assumptions are that NVIDIA maintains consistent versioning and architecture naming conventions. Consider the "Auto" case: it *assumes* the detected architecture is a valid target.

* **User Errors:**  The validation logic in `_validate_nvcc_arch_args` anticipates common mistakes like providing invalid architecture names or misusing the special keywords.

**5. Tracing User Operations:**

Think about how a developer using Frida might end up using this code. The likely scenario is that they are building a Frida gadget or plugin that includes CUDA code. The `meson.build` file would use this module to configure the CUDA compilation process. The user wouldn't directly interact with *this specific Python file*, but rather through the Meson build system's DSL.

**6. Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, addressing each point in the prompt with specific examples from the code. Use bullet points and clear headings to enhance readability. Be explicit about the relationship (or lack thereof) to each concept (e.g., directly involved vs. indirectly related).

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe this module *directly executes* CUDA code. **Correction:**  No, it *configures the *compilation* of CUDA code.
* **Overly focusing on the Frida aspect:** While it's *for* Frida, the core logic is about CUDA compilation. Keep the focus on the CUDA aspects within the Frida context.
* **Not enough specific code examples:** Go back and pull out key lines of code to illustrate the points being made (e.g., the `version_compare` calls, the `driver_version_table`, the `-gencode` flag construction).

By following these steps, we can systematically analyze the code and provide a comprehensive answer to the prompt's questions.
This Python code file, `cuda.py`, is a module within the Meson build system specifically designed to handle CUDA-related build configurations for the Frida dynamic instrumentation toolkit. Let's break down its functionalities:

**Core Functionalities:**

1. **Determining Minimum CUDA Driver Version:**
   - The `min_driver_version` method takes a CUDA Toolkit version string as input and returns the minimum required NVIDIA driver version for that toolkit on either Windows or Linux.
   - It uses a lookup table (`driver_version_table`) that maps CUDA Toolkit versions to the corresponding minimum driver versions for different operating systems.

2. **Generating NVCC Architecture Flags:**
   - The `nvcc_arch_flags` and `nvcc_arch_readable` methods are responsible for generating the appropriate architecture flags to be passed to the NVIDIA CUDA Compiler (NVCC). These flags tell the compiler which GPU architectures to target during compilation.
   - `nvcc_arch_flags` returns the actual compiler flags (e.g., `-gencode arch=compute_75,code=sm_75`).
   - `nvcc_arch_readable` returns a more human-readable representation of the target architectures (e.g., `sm_75`).
   - These methods take the CUDA Toolkit version and a list of target architectures (or special keywords like "All", "Common", "Auto") as input.
   - They use a complex logic within the `_nvcc_arch_flags` method to map CUDA versions and desired architectures to the correct NVCC flags. This logic includes handling different CUDA Toolkit versions and their supported architectures, as well as special keywords for convenience.

**Relationship to Reverse Engineering:**

This module indirectly relates to reverse engineering in the following ways:

* **Targeting Specific GPU Architectures:** When building Frida with CUDA support, this module ensures that the generated code is compatible with the intended target GPU architectures. A reverse engineer analyzing a Frida gadget or plugin built with CUDA would need to understand which GPU architectures were targeted during compilation. The architecture flags generated by this module provide that information.
    * **Example:** If `nvcc_arch_flags` generates `-gencode arch=compute_80,code=sm_80`, a reverse engineer knows that the CUDA code was compiled to target GPUs with Compute Capability 8.0 (Ampere architecture). They would then focus their analysis on the specific features and instructions available on those architectures.

**Involvement of Binary Bottom, Linux/Android Kernel & Framework Knowledge:**

This module touches upon these areas:

* **Binary Bottom (GPU Architecture):** The core functionality revolves around specifying GPU architectures (`sm_XX`, `compute_XX`). These are low-level identifiers representing the specific instruction sets and features of different NVIDIA GPU architectures. The module contains knowledge about which architectures are supported by different CUDA Toolkit versions.
    * **Example:** The code has explicit handling for architectures like "Fermi", "Kepler", "Maxwell", "Pascal", "Volta", "Turing", and "Ampere", which are all specific NVIDIA GPU microarchitectures with different binary instruction sets.

* **Linux (Driver Interaction):** The `min_driver_version` method considers the operating system (Linux or Windows) when determining the minimum driver version. This is because driver compatibility can vary between operating systems. The driver is a crucial piece of software that allows the operating system kernel to interact with the GPU hardware at a low level.
    * **Example:**  For CUDA Toolkit version ">=12.0.0", the minimum driver version on Linux is '525.60.13', while on Windows it's '527.41'. This reflects the different driver release schedules and compatibility considerations for each OS.

* **Android (Indirectly):** While not explicitly mentioned, Frida is often used for instrumentation on Android. If Frida is built with CUDA support for an Android environment (which might involve cross-compilation), this module would still be used to generate the appropriate architecture flags for the target Android GPU (which is often an integrated NVIDIA GPU). The underlying principles of GPU architecture and driver compatibility remain the same.

**Logical Reasoning (Hypothetical Input & Output):**

Let's consider the `nvcc_arch_flags` method:

**Hypothetical Input:**

* `cuda_version`: "11.5"
* `arch_list`: ["Auto"]
* `detected`: ["7.0", "7.5"]  (Assume the build system detected GPUs with Compute Capabilities 7.0 and 7.5)

**Logical Steps within `_nvcc_arch_flags`:**

1. The code recognizes "Auto" and uses the `detected` architectures.
2. It filters the `detected` list based on the CUDA version (11.5) and its supported range. For CUDA 11.5, the lower limit is '3.5'. Both 7.0 and 7.5 are within the supported range.
3. It generates `-gencode` flags for each detected architecture:
   - For 7.0: `-gencode arch=compute_70,code=sm_70` and `-gencode arch=compute_70,code=compute_70`
   - For 7.5: `-gencode arch=compute_75,code=sm_75` and `-gencode arch=compute_75,code=compute_75`

**Hypothetical Output of `nvcc_arch_flags`:**

```
['-gencode', 'arch=compute_70,code=sm_70',
 '-gencode', 'arch=compute_70,code=compute_70',
 '-gencode', 'arch=compute_75,code=sm_75',
 '-gencode', 'arch=compute_75,code=compute_75']
```

**User or Programming Common Usage Errors:**

1. **Providing an Invalid CUDA Toolkit Version:**
   - **Example:**  Calling `min_driver_version` with a non-existent or incorrectly formatted CUDA version string (e.g., "15.0" when it doesn't exist in the table, or "11.5.a").
   - **Result:** The `min_driver_version` method might return "unknown" or raise an error if the version comparison logic fails.

2. **Incorrectly Specifying Target Architectures:**
   - **Example:** Providing an architecture name that is not recognized by the CUDA Toolkit version being used (e.g., trying to target "sm_90" with an older CUDA Toolkit).
   - **Result:** The `_nvcc_arch_flags` method will raise an `InvalidArguments` exception with a message like "Unknown CUDA Architecture Name sm_90!".

3. **Misusing Special Architecture Keywords:**
   - **Example:** Providing `arch_list=["All", "sm_70"]`. The code explicitly checks for this and raises an `InvalidArguments` exception because "All" is meant to be used alone.

**User Operation Steps Leading Here (Debugging Clues):**

A user (likely a developer building Frida) would typically interact with this code indirectly through the Meson build system. Here's a potential sequence:

1. **User Configures Build:** The user runs a Meson configuration command, specifying options to enable CUDA support. This might involve setting a build option like `-Dwith_cuda=true` or similar.

2. **Meson Processes Configuration:** Meson reads the `meson.build` files in the Frida project, including the one that utilizes the `cuda.py` module.

3. **`cuda.py` is Invoked:** When the build system needs to compile CUDA code, it will call functions from the `cuda.py` module to determine the necessary compiler flags and minimum driver versions.

4. **Error Encountered (Hypothetical):** Let's say the user has an old NVIDIA driver installed. When Meson calls `cuda.py` with the detected CUDA Toolkit version, `min_driver_version` might return a version higher than the installed driver.

5. **Build System Reports Error:** Meson, based on the output of `min_driver_version`, can then report an error to the user, indicating that their driver version is too old and needs to be updated.

**Debugging Clues from the Code:**

* **Stack Traces:** If an error occurs within this module (e.g., `InvalidArguments`), the Python stack trace will point to the specific line in `cuda.py` where the error originated.
* **Logging (If Added):**  Developers of the Frida build system might add logging statements within `cuda.py` to track the values of variables (like the detected CUDA version, target architectures) during the build process. This would provide valuable insights for debugging.
* **Meson's Build Log:** Meson itself generates a build log, which might contain information about the commands executed, including the NVCC commands with the flags generated by this module. Examining these commands can reveal if the correct architecture flags are being used.
* **Configuration Options:** Understanding the Meson configuration options related to CUDA can help trace how the build system decided to invoke this module and with what parameters.

In summary, `cuda.py` is a crucial component for building Frida with CUDA support, handling the complexities of NVIDIA's driver and architecture ecosystem within the Meson build environment. It plays an indirect role in reverse engineering by providing information about the target GPU architectures and involves low-level knowledge of GPU hardware and operating system interactions.

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/modules/cuda.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```