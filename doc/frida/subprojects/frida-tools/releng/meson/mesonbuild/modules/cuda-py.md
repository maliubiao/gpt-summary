Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding - What is this code doing?**

The first step is always to get a high-level overview. The file name `cuda.py` within a `mesonbuild/modules` directory strongly suggests this code deals with CUDA integration in the Meson build system. The imports confirm this, referencing `CudaCompiler` and other Meson-specific classes. The core purpose seems to be providing Meson users with tools to manage CUDA compilation settings.

**2. Identifying Key Functions and Their Roles:**

Next, I'd scan the class `CudaModule` and its methods. The docstrings and method names are crucial here:

* `min_driver_version`:  This clearly relates to determining the minimum required NVIDIA driver version for a given CUDA toolkit version.
* `nvcc_arch_flags`: This suggests generating compiler flags for `nvcc` (the NVIDIA CUDA compiler) related to architecture.
* `nvcc_arch_readable`: This seems similar to the previous one but likely returns a more human-readable representation of the architecture flags.

**3. Deeper Dive into Functionality - How do they work?**

Now, let's examine the internal workings of each key function:

* **`min_driver_version`:** The logic here is straightforward. It has a hardcoded table mapping CUDA toolkit versions to minimum driver versions for Windows and Linux. It iterates through this table to find the appropriate driver version based on the input CUDA toolkit version.

* **`nvcc_arch_flags` and `nvcc_arch_readable`:**  These functions share a lot of logic. The helper functions `_validate_nvcc_arch_args` and `_nvcc_arch_flags` are key.
    * `_validate_nvcc_arch_args`: This function parses the arguments, handling different ways of specifying the target architectures (strings, lists, special keywords like "All", "Common", "Auto"). It also handles the `detected` keyword argument.
    * `_nvcc_arch_flags`: This is the core logic. It contains a large conditional block that evolves based on the CUDA toolkit version. This block defines known GPU architectures, common architectures, and upper/lower limits. It then uses the provided or detected architecture list to generate the appropriate `-gencode` flags for `nvcc`.

**4. Connecting to Reverse Engineering:**

Now comes the task of relating the functionality to reverse engineering. The key connection is **targeting specific GPU architectures**.

* **Why is this relevant?** When reverse engineering CUDA applications, it's often useful to analyze the code generated for specific GPU architectures. Understanding which architectures are targeted by the compiled binary can help in setting up the appropriate environment for analysis or debugging. For example, you might need a specific NVIDIA driver or a GPU with a certain compute capability.

* **Example:** If a reverse engineer sees that a CUDA binary was compiled with flags including `sm_50`, they know that the binary is targeting Maxwell GPUs. This information can guide their analysis efforts.

**5. Connecting to Binary/Low-Level Concepts:**

The connection here lies in the concept of **GPU architectures and instruction sets**.

* **Explanation:** CUDA code is compiled for specific GPU architectures. Each architecture has its own set of instructions and features (compute capabilities). The `-gencode` flags control which architectures the compiler targets, generating specific machine code (SASS) or intermediate representation (PTX) for those architectures.

* **Linux/Android Kernel/Framework:** While this specific Python code doesn't directly interact with the Linux or Android kernel, the *result* of its operation (the generated `nvcc` flags) directly impacts the compiled CUDA code that *will* run on these systems. The driver versions managed by this code are kernel-level components. On Android, the CUDA framework resides within the Android system image.

**6. Logical Reasoning (Hypothetical Inputs/Outputs):**

To demonstrate logical reasoning, I considered some simple use cases:

* **Input:** `min_driver_version("11.5.0")` on a Linux system.
* **Output:** `"495.29.05"` (by looking up the table).

* **Input:** `nvcc_arch_flags(compiler, ["Auto"])` where `compiler` is a `CudaCompiler` object that detects the current GPU architecture as "sm_75".
* **Output:**  Likely a list of `-gencode` flags targeting "sm_75" (after filtering based on CUDA version).

**7. Common User Errors:**

I considered potential mistakes users might make:

* **Incorrect CUDA version:** Providing a wrong or misspelled CUDA toolkit version to `min_driver_version`.
* **Conflicting architecture specifications:**  Providing contradictory architecture lists or using special keywords incorrectly in `nvcc_arch_flags`.
* **Outdated drivers:** Trying to run CUDA code compiled for a newer architecture on a system with an older driver (which `min_driver_version` helps prevent).

**8. Debugging Clues - How does a user get here?**

The "debugging clues" section requires tracing the user's actions within the Frida build process:

1. **User wants to build Frida with CUDA support.** This is the initial intent.
2. **Meson is used as the build system.** Frida uses Meson for its builds.
3. **Meson encounters CUDA-related build targets.** The `meson.build` files would contain logic to conditionally enable CUDA support.
4. **The `cuda.py` module is invoked.** When Meson processes these CUDA-related targets, it uses the `cuda.py` module to determine compiler flags and driver requirements.
5. **A problem arises.** The user might encounter a build error related to CUDA, incorrect driver versions, or architecture mismatches.
6. **The user investigates the Meson build logs.** The logs might show the specific calls to the `cuda` module functions and the arguments used.
7. **The user might examine the `build.ninja` file.** This file generated by Meson shows the exact commands executed, including the `nvcc` calls with the flags generated by `cuda.py`.
8. **The user might then look at the `cuda.py` source code** to understand how the flags and requirements are being determined.

This step-by-step flow connects the user's high-level goal to the specific lines of code in `cuda.py`, explaining how a user debugging a CUDA-related build issue might end up examining this file.
This Python code file, `cuda.py`, is a module within the Meson build system that provides functionality related to building software that uses NVIDIA's CUDA platform. Frida, being a dynamic instrumentation toolkit, can leverage CUDA for performance-sensitive tasks, especially when targeting platforms with GPUs.

Here's a breakdown of its functions and their relevance:

**Functionality:**

1. **`min_driver_version(cuda_version)`:**
   - **Purpose:** Determines the minimum required NVIDIA driver version for a given CUDA Toolkit version.
   - **How it works:** It contains a hardcoded table mapping CUDA Toolkit versions to the minimum compatible driver versions for Windows and Linux. It uses the `version_compare` function (from Meson) to find the appropriate entry in the table based on the input `cuda_version`.
   - **Output:** Returns a string representing the minimum driver version (e.g., "527.41").

2. **`nvcc_arch_flags(compiler_or_version, *arches, detected=None)`:**
   - **Purpose:** Generates the necessary `nvcc` (NVIDIA CUDA Compiler) flags to target specific GPU architectures.
   - **How it works:**
     - Takes the CUDA compiler object or its version string as input.
     - Takes a list of target GPU architectures (e.g., "sm_50", "compute_70", "Auto", "All", "Common").
     - Optionally accepts a `detected` keyword argument, which can be a list of detected GPU architecture strings.
     - It uses a complex internal logic (`_nvcc_arch_flags`) that depends on the CUDA Toolkit version to determine the appropriate `-gencode` flags. This logic maps symbolic architecture names (like "Maxwell", "Pascal") and compute capabilities (like "sm_50") to the specific compiler flags.
     - It handles special keywords like "Auto" (detects and uses the architecture of the current GPU), "All" (targets all known architectures for the given CUDA version), and "Common" (targets a set of commonly used architectures).
   - **Output:** Returns a list of strings representing the `nvcc` flags (e.g., `['-gencode', 'arch=compute_50,code=sm_50']`).

3. **`nvcc_arch_readable(compiler_or_version, *arches, detected=None)`:**
   - **Purpose:** Similar to `nvcc_arch_flags`, but returns a more human-readable list of the targeted architectures.
   - **How it works:**  It calls the same internal logic as `nvcc_arch_flags` but returns the second element of the tuple returned by `_nvcc_arch_flags`, which is a list of readable architecture strings (e.g., `['sm_50']`).
   - **Output:** Returns a list of strings representing the readable architecture names (e.g., `['sm_50']`).

**Relationship to Reverse Engineering:**

This module directly relates to reverse engineering in the following ways:

* **Targeting Specific GPU Architectures:** When reverse engineering a CUDA application, understanding which GPU architectures it was compiled for is crucial. This module allows the build system to precisely control the target architectures using flags like `-gencode arch=compute_XX,code=sm_YY`. A reverse engineer might need to recompile parts of the application or create tools targeting the same architectures to ensure compatibility and proper interaction.

   **Example:** A reverse engineer analyzing a game that uses CUDA might find that it targets "sm_60" (Pascal architecture). To effectively hook and analyze the CUDA kernels, they might need to use Frida scripts that are also aware of this architecture, or they might need to build custom CUDA tools targeting the same architecture for deeper analysis.

* **Driver Compatibility:**  The `min_driver_version` function is essential for ensuring that the compiled CUDA application will run on the target system. Reverse engineers often need to set up specific environments to run and analyze applications. Knowing the minimum driver version is a crucial piece of information for setting up a compatible test environment.

   **Example:** If `min_driver_version("11.0.3")` returns "450.51.06" for Linux, a reverse engineer knows that the system they use for analyzing applications built with CUDA 11.0.3 must have at least this driver version installed.

**Relevance to Binary/Low-Level, Linux/Android Kernel & Framework:**

* **Binary Level:** The `-gencode` flags directly influence the binary code generated by the `nvcc` compiler. They determine which Specific Architecture Assembly (SASS) or Parallel Thread Execution (PTX) intermediate representation will be included in the compiled binary. This is the low-level code that will be executed on the GPU.

   **Example:** The flag `-gencode arch=compute_70,code=sm_70` tells the compiler to generate SASS code optimized for the Volta architecture (sm_70) and also include the compute capability definition for compute_70.

* **Linux/Android Kernel:** The minimum driver version directly relates to the kernel-level NVIDIA driver. The CUDA runtime and the applications built with CUDA rely on the kernel driver for interacting with the GPU hardware. On Android, the CUDA libraries and drivers are part of the Android system image.

   **Example:** The `min_driver_version` function helps ensure that the Frida gadget (the agent injected into the target process) built with CUDA dependencies will be compatible with the NVIDIA drivers present on the target Linux or Android system.

* **Framework (CUDA Runtime):** This module helps in building applications that rely on the CUDA runtime environment. The generated `nvcc` flags ensure that the compiled code is compatible with the specific version of the CUDA runtime libraries that will be available on the target system.

**Logical Reasoning (Hypothetical Input & Output):**

**Scenario 1 (min_driver_version):**

* **Input:** `cuda_version = "11.6.0"`
* **Assumptions:** The code is run on a Linux system.
* **Logic:** The code will iterate through the `driver_version_table` and find the entry where `'cuda_version'` is `>=11.6.0`. It will then return the value associated with the `'linux'` key in that entry.
* **Output:** `"510.39.01"`

**Scenario 2 (nvcc_arch_flags):**

* **Input:** `compiler_version = "10.2.89"`, `arches = ["Auto"]`, `detected = ["sm_75"]`
* **Assumptions:** The target system has a GPU with architecture "sm_75".
* **Logic:**
    - The `_validate_nvcc_arch_args` function will process the input.
    - `_nvcc_arch_flags` will be called with the CUDA version and the target architectures. Since `arches` is "Auto" and `detected` is provided, it will likely target the detected architecture (sm_75), taking into account the CUDA version's supported architectures.
    - For CUDA 10.2, "sm_75" (Turing) is a valid architecture.
* **Output:** `['-gencode', 'arch=compute_75,code=sm_75']`

**Common User/Programming Errors:**

1. **Incorrect CUDA Version in `min_driver_version`:**
   - **Example:** Calling `min_driver_version("invalid_version")`. This will likely not match any entry in the table, and the function will return the default "unknown" or potentially raise an error if input validation is stricter.
   - **Debugging:** The user might see "unknown" as the minimum driver version and be confused. They should double-check the CUDA Toolkit version they are targeting.

2. **Conflicting Architectures in `nvcc_arch_flags`:**
   - **Example:** Calling `nvcc_arch_flags("11.0", "All", "sm_30")`. This is redundant and potentially confusing. "All" already implies targeting a wide range of architectures.
   - **Debugging:** While this might not directly cause an error, it could lead to unnecessarily large binaries and potentially performance issues if the application is only intended for a specific architecture. Meson might issue a warning about redundant flags.

3. **Providing Architectures Not Supported by the CUDA Version:**
   - **Example:** Calling `nvcc_arch_flags("8.0", "sm_80")`. "sm_80" (Ampere) is not supported by CUDA 8.0.
   - **Debugging:** `nvcc` will likely throw an error during compilation indicating an invalid architecture. The user would need to check the supported architectures for their CUDA Toolkit version.

4. **Misunderstanding "Auto" in `nvcc_arch_flags`:**
   - **Example:** Assuming "Auto" will magically work on any system without considering the `detected` argument. If `detected` is not provided or the detection fails, "Auto" might default to a common set of architectures, which might not be optimal for the specific target GPU.
   - **Debugging:** The compiled application might not be using the GPU efficiently, or it might not run on systems with different GPU architectures than what was assumed by the "Auto" setting.

**User Operations Leading to This Code (Debugging Clues):**

1. **User wants to build Frida with CUDA support:** This is the initial step. The user likely has some CUDA-based components they want to include in their Frida build.
2. **Meson build system is used:** Frida uses Meson as its build system.
3. **Meson processes the `meson.build` files:**  The `meson.build` files will contain logic that detects the CUDA SDK and uses the `cuda` module to configure the build.
4. **The `cuda.py` module is invoked:** When Meson encounters CUDA-related targets (e.g., libraries or executables that need to be compiled with `nvcc`), it will use the functions in `cuda.py` to determine the correct compiler flags.
5. **A problem arises during the build:** The user might encounter errors like:
   - **Compilation errors from `nvcc`:**  This could be due to incorrect architecture flags generated by `nvcc_arch_flags`.
   - **Linker errors:**  Potentially related to CUDA libraries not being found or incompatible architecture targets.
   - **Runtime errors:** The compiled Frida gadget might fail to load or function correctly on the target device if the CUDA driver is too old or the architecture is mismatched.
6. **The user investigates the Meson build log:** The build log will show the exact commands executed by Meson, including the calls to `nvcc` with the generated flags. This might point to issues with the architecture flags.
7. **The user might examine the `build.ninja` file:** This file generated by Meson contains the detailed build rules. Examining the `nvcc` commands can reveal the specific architecture flags being used.
8. **The user might then look at the `frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/cuda.py` source code:** To understand how the architecture flags are being generated, why a specific minimum driver version is required, or to debug potential issues in the CUDA integration logic within the build system. They might set breakpoints or add print statements to understand the values of variables and the flow of execution within this module.

In essence, this `cuda.py` module is a crucial part of Frida's build system when CUDA support is involved. Users interacting with this code are typically developers working on Frida itself or users trying to build a custom Frida with CUDA dependencies and encountering build or runtime issues related to CUDA.

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/cuda.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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