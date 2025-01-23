Response:
Let's break down the thought process for analyzing this Python code and fulfilling the request.

**1. Understanding the Goal:**

The core request is to analyze a specific Python file (`cuda.py`) within the Frida project and explain its functionality, relate it to reverse engineering, discuss its connections to low-level concepts, explain its logic, identify potential user errors, and trace the user's path to reach this code.

**2. Initial Code Inspection (High-Level):**

* **File Path:** `frida/subprojects/frida-core/releng/meson/mesonbuild/modules/cuda.py`. The path itself suggests this file is part of Frida's build system (Meson) and specifically deals with CUDA support.
* **Imports:**  Standard Python imports (`re`, `typing`), Meson-specific imports (`mesonlib`, `compilers.cuda`, `interpreter.*`), and internal module imports. This reinforces the idea of a build system integration for CUDA.
* **Class `CudaModule`:** This is the central class, inheriting from `NewExtensionModule`. It contains methods related to CUDA. This immediately suggests a modular approach for handling CUDA functionalities within the build process.
* **Methods:** `min_driver_version`, `nvcc_arch_flags`, `nvcc_arch_readable`. These names are quite descriptive and hint at the core functionalities: determining minimum driver versions and managing NVCC (NVIDIA CUDA Compiler) architecture flags.

**3. Deeper Dive into Functionality (Method by Method):**

* **`min_driver_version`:**
    * **Purpose:**  Given a CUDA Toolkit version, it returns the minimum required NVIDIA driver version for that toolkit.
    * **Logic:**  It uses a hardcoded lookup table (`driver_version_table`) to find the corresponding driver version based on the provided CUDA version and the operating system.
    * **Relevance to Reverse Engineering:** While not directly involved in the *act* of reverse engineering, this function is crucial for setting up the environment required to *run* or interact with CUDA-enabled applications that might be the target of reverse engineering. Knowing the minimum driver helps ensure compatibility.
    * **Low-Level Connection:**  Driver versions directly interact with the kernel and hardware. This function indirectly touches upon these low-level aspects by ensuring the correct driver is in place.
    * **Logic Example:** Input: "11.5.0", Output (Linux): "495.29.05".
    * **User Error:** Providing an invalid CUDA version string will cause an error.
* **`nvcc_arch_flags` and `nvcc_arch_readable`:**
    * **Purpose:** These functions generate the NVCC command-line flags related to target GPU architectures. `nvcc_arch_flags` returns the flags themselves (e.g., `-gencode arch=compute_80,code=sm_80`), while `nvcc_arch_readable` returns a more readable representation (e.g., `sm_80`).
    * **Logic:** They take the CUDA Toolkit version and a list of target architectures as input. They have complex logic to map symbolic architecture names (like "Ampere") to specific compute capabilities and SM versions. They handle special keywords like "All", "Common", and "Auto".
    * **Relevance to Reverse Engineering:**  Crucially important! When reverse engineering CUDA applications, you might need to compile or recompile parts of the code. Knowing the correct architecture flags ensures the compiled code runs on the intended hardware. You might need to analyze different architecture binaries.
    * **Low-Level Connection:**  Target architectures directly relate to the capabilities of the GPU hardware. The generated flags tell the compiler what instruction sets and features to target.
    * **Logic Example:** Input (CUDA 11.0, ["Ampere"]), Output (`nvcc_arch_flags`): `['-gencode', 'arch=compute_80,code=sm_80']`. Output (`nvcc_arch_readable`): `['sm_80']`.
    * **User Error:** Providing invalid architecture names, or using "All/Common/Auto" with other architectures incorrectly will cause errors.
* **Helper Functions (`_break_arch_string`, `_detected_cc_from_compiler`, `_validate_nvcc_arch_args`, `_filter_cuda_arch_list`, `_nvcc_arch_flags`):**  These break down the complexity of the main functions. They handle string parsing, validation, and the core logic of mapping architectures.

**4. Connecting to Broader Concepts:**

* **Build Systems (Meson):** Recognize that this code is part of a build system. Its purpose is to automate the process of compiling and linking software, especially when dealing with complex dependencies and hardware targets like GPUs.
* **CUDA Ecosystem:**  Understand that this code interacts with the CUDA Toolkit (NVCC, libraries, etc.) and the underlying NVIDIA drivers.
* **GPU Architecture:**  Realize the importance of targeting specific GPU architectures for performance and compatibility.

**5. Tracing the User's Path (Debugging Clue):**

This is a bit more speculative but involves understanding how a user might interact with Frida and its build process:

* **User wants to build Frida with CUDA support.**
* **Frida's build system (likely Meson) needs to determine the correct compiler flags for CUDA.**
* **Meson uses modules like this `cuda.py` to handle platform-specific logic.**
* **The user might encounter issues related to driver versions or architecture compatibility, leading them to investigate the build process.**
* **They might examine the Meson build files or the Frida source code, eventually finding this `cuda.py` file.**

**6. Structuring the Answer:**

Organize the findings into logical sections as requested:

* **Functionality:** List the main functions and their purposes.
* **Relationship to Reverse Engineering:** Provide concrete examples of how these functions are relevant.
* **Low-Level Concepts:** Explain the connections to the kernel, drivers, and hardware architecture.
* **Logic and Examples:**  Illustrate the input and output of key functions with examples.
* **User Errors:**  Point out common mistakes users might make.
* **User's Path:**  Describe the likely steps a user would take to encounter this file during debugging or investigation.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Focus only on the individual functions.
* **Correction:**  Realize the importance of the context within the build system and Frida's overall purpose.
* **Initial thought:** Provide very technical explanations of CUDA architectures.
* **Correction:**  Balance technical detail with clarity for a broader audience. Focus on the *relevance* to reverse engineering rather than a deep dive into GPU architecture.
* **Initial thought:**  The "user path" is too abstract.
* **Correction:** Make it more concrete by linking it to a potential debugging scenario and interaction with the build system.

By following these steps, combining code inspection, domain knowledge (CUDA, build systems, reverse engineering), and logical reasoning, we arrive at a comprehensive and informative answer that addresses all aspects of the prompt.
This Python code file, `cuda.py`, is a module for the Meson build system that provides functionalities related to working with NVIDIA's CUDA toolkit. Since Frida uses Meson for its build process, this module helps manage the compilation of CUDA code within Frida.

Here's a breakdown of its functions and their relevance:

**Functionality:**

1. **`min_driver_version(self, state, args, kwargs)`:**
   - **Purpose:**  Given a CUDA Toolkit version string, it returns the minimum required NVIDIA driver version for that toolkit version to function correctly.
   - **How it works:** It uses a hardcoded lookup table (`driver_version_table`) that maps CUDA Toolkit versions to the corresponding minimum driver versions for Windows and Linux.
   - **Relevance:** This ensures that when Frida is built with CUDA support, the build system can check if the user has a compatible NVIDIA driver installed.

2. **`nvcc_arch_flags(self, state, args, kwargs)`:**
   - **Purpose:**  Generates the appropriate NVCC (NVIDIA CUDA Compiler) flags for targeting specific GPU architectures. This is crucial for compiling CUDA code that will run on different NVIDIA GPUs.
   - **How it works:**
     - It takes the CUDA Toolkit version and a list of target architectures (like "Auto", "Common", specific architecture names like "Ampere", or compute capabilities like "sm_80") as input.
     - It uses internal logic and lookup tables to translate these architectural specifications into the correct NVCC flags (e.g., `-gencode arch=compute_80,code=sm_80`).
     - It handles special keywords like "All" (all known architectures), "Common" (commonly used architectures), and "Auto" (detect architectures based on the compiler or provided `detected` list).
   - **Relevance:** This is vital for reverse engineering CUDA-accelerated applications. When you analyze such applications, you might need to recompile parts of the code or understand which GPU architectures the original code was targeting.

3. **`nvcc_arch_readable(self, state, args, kwargs)`:**
   - **Purpose:** Similar to `nvcc_arch_flags`, but instead of generating compiler flags, it returns a list of human-readable architecture names (e.g., "sm_80", "compute_75") based on the input CUDA version and target architectures.
   - **How it works:** It uses the same underlying logic as `nvcc_arch_flags` but extracts the readable names instead of the compiler flag strings.
   - **Relevance:** Useful for understanding the targeted architectures without needing to parse the raw NVCC flags. This can be helpful during the reverse engineering process to quickly identify the intended hardware.

**Relationship to Reverse Engineering:**

* **Targeted Hardware:** When reverse engineering CUDA applications, understanding the targeted GPU architectures is crucial. `nvcc_arch_flags` and `nvcc_arch_readable` help determine these architectures, allowing you to focus your analysis on the relevant GPU instruction sets and features. For example, if the code was compiled with flags targeting "sm_80" (Ampere architecture), you know to look for features and instructions specific to that generation of NVIDIA GPUs.
* **Recompilation/Modification:** If you need to modify or recompile parts of a CUDA application you are reverse engineering (e.g., to add instrumentation or fix bugs), you'll need to use NVCC with the correct architecture flags. This module provides the logic to generate those flags, ensuring your modifications are compatible with the intended hardware.
* **Understanding Build Processes:**  Reverse engineers often need to understand the build processes of the software they are analyzing. This module reveals how Frida's build system handles CUDA compilation, which can provide insights into how the target application might have been built.

**Connections to Binary Bottom, Linux, Android Kernel & Framework:**

* **Binary Bottom:** The NVCC flags generated by this module directly influence the machine code (binary) produced by the compiler for the GPU. Targeting different architectures results in different sets of instructions and optimizations in the final binary.
* **Linux:** The `min_driver_version` function has specific driver version mappings for Linux, acknowledging the OS-specific nature of drivers. Frida often runs on Linux systems used for mobile reverse engineering (like Android).
* **Android Kernel & Framework:** While this specific module doesn't directly interact with the Android kernel or framework code, CUDA is used on Android devices with NVIDIA GPUs. Frida's ability to work with CUDA code is relevant to reverse engineering applications and system components that leverage GPU acceleration on Android. Understanding how CUDA is built and targeted is important in that context.

**Logic and Examples:**

**`min_driver_version`:**

* **Assumption:** The user is building Frida and has specified that CUDA support should be included. The build system detects a CUDA toolkit installation.
* **Input:** CUDA Toolkit version string, e.g., "11.6.0".
* **Output (Linux):** "510.39.01" (the minimum required driver version for that CUDA version on Linux).
* **Output (Windows):** "511.23"

**`nvcc_arch_flags`:**

* **Assumption:** The build system needs to compile CUDA code and wants to target specific GPU architectures for optimal performance or broad compatibility.
* **Input (CUDA Version as string):** "11.0", ["Auto"]
* **Output:**  Potentially `['-gencode', 'arch=compute_35,code=sm_35', '-gencode', 'arch=compute_50,code=sm_50', '-gencode', 'arch=compute_60,code=sm_60', '-gencode', 'arch=compute_70,code=sm_70', '-gencode', 'arch=compute_80,code=sm_80']` (This assumes "Auto" resolves to common architectures for CUDA 11.0).
* **Input (CUDA Compiler object):** A `CudaCompiler` object representing the detected CUDA compiler, ["Ampere"]
* **Output:** `['-gencode', 'arch=compute_80,code=sm_80']`

**`nvcc_arch_readable`:**

* **Assumption:**  Same as `nvcc_arch_flags`, but the goal is to get human-readable names.
* **Input (CUDA Version as string):** "11.0", ["Common"]
* **Output:** `['sm_35', 'compute_35', 'sm_50', 'compute_50', 'sm_60', 'compute_60', 'sm_70', 'compute_70', 'sm_80', 'compute_80']` (Readable names for common architectures in CUDA 11.0).

**User or Programming Common Usage Errors:**

1. **Incorrect CUDA Toolkit Version in `min_driver_version`:**
   - **Input:** `cuda.min_driver_version(state, ["invalid_version"], {})`
   - **Error:** `InvalidArguments: min_driver_version must have exactly one positional argument: a CUDA Toolkit version string...`
   - **Explanation:** The function expects a valid CUDA version string. Providing something else will lead to an error.

2. **Invalid Architecture Names in `nvcc_arch_flags` or `nvcc_arch_readable`:**
   - **Input:** `cuda.nvcc_arch_flags(state, ["11.0", "NonExistentArch"], {})`
   - **Error:** `InvalidArguments: Unknown CUDA Architecture Name NonExistentArch!`
   - **Explanation:** The module doesn't recognize "NonExistentArch" as a valid CUDA architecture name.

3. **Mixing Special Architectures with Others:**
   - **Input:** `cuda.nvcc_arch_flags(state, ["11.0", "All", "sm_80"], {})`
   - **Error:** `InvalidArguments: The special architectures 'All', 'Common' and 'Auto' must appear alone, as a positional argument!`
   - **Explanation:**  Keywords like "All" are meant to be used in isolation to represent all or common architectures, not combined with specific ones.

**User Operation Steps to Reach Here (as a debugging clue):**

1. **User attempts to build Frida with CUDA support:** This typically involves configuring the build system (Meson) with options to enable CUDA. For example, in the `meson_options.txt` file or via command-line arguments like `-Dcuda=enabled`.
2. **Meson executes the build configuration:** During this phase, Meson will parse the `meson.build` files and execute various modules, including this `cuda.py` module.
3. **Meson needs to determine the minimum required driver version:**  If the build scripts use the `cuda.min_driver_version` function, Meson will call this function with the detected CUDA Toolkit version.
4. **Meson needs to compile CUDA code:** When the build process reaches the point where CUDA source files need to be compiled, Meson will use the `cuda.nvcc_arch_flags` function to generate the correct NVCC flags based on the target architectures specified in the build configuration or detected automatically.
5. **User encounters a build error related to CUDA:**  For example, an error message indicating an incompatible driver version or issues with architecture flags.
6. **User investigates the Meson build files or Frida's source code:** To understand the error, the user might start looking at the `meson.build` files involved in the CUDA compilation process.
7. **User traces the execution of Meson modules:** By examining the build logs or stepping through the Meson code (if they are familiar with it), the user might identify that the `cuda.py` module is involved in the problematic step.
8. **User opens `frida/subprojects/frida-core/releng/meson/mesonbuild/modules/cuda.py`:**  To understand *how* the driver version is checked or the architecture flags are generated, the user would open this specific source file.

In essence, a user would typically arrive at this file while troubleshooting issues related to CUDA compilation within the Frida build process, trying to understand how Frida manages CUDA dependencies and compilation settings.

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/modules/cuda.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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