Response:
The user wants to understand the functionality of the provided Python code. This code is a module named `cuda.py` within the `mesonbuild` project, which is part of the Meson build system. It seems to provide functionality related to CUDA compilation.

Here's a breakdown of the requested information and a plan to address it:

1. **Functionality:** I need to go through each method in the `CudaModule` class and describe what it does.
2. **Relationship to Reversing:** I need to identify if any of the functionalities offered by this module could be relevant in the context of reverse engineering. This would likely involve understanding how CUDA is used in software and how manipulating compilation flags could be useful.
3. **Binary/Kernel/Framework Knowledge:** I need to pinpoint aspects of the code that demonstrate understanding of low-level concepts like binary code generation, Linux/Android kernel interactions (though this seems less likely given the CUDA focus), and potentially framework-specific knowledge related to CUDA.
4. **Logical Reasoning (Input/Output):**  For methods that perform some form of logic or computation, I need to create hypothetical inputs and predict the corresponding outputs.
5. **Common Usage Errors:** I need to think about how a user might misuse this module based on the parameters and logic involved.
6. **User Operation to Reach Here (Debugging Clue):** I need to outline the steps a user (likely a developer using the Meson build system) might take that would lead to this specific code being executed.

**Detailed Plan:**

* **`min_driver_version`:**
    * Functionality: Look up the minimum required NVIDIA driver version for a given CUDA Toolkit version.
    * Reversing: Less directly related. Might be relevant if reverse engineering a CUDA application and needing to understand its environment requirements.
    * Binary/Kernel/Framework:  Relates to the interaction between user-space CUDA libraries and the kernel-level driver.
    * Input/Output:  Input: CUDA Toolkit version string (e.g., "11.6.0"). Output: Minimum driver version string (e.g., "511.23").
    * Usage Errors: Providing a non-string or incorrect CUDA version.
    * User Path: Configuring build options in Meson that trigger checks related to CUDA compatibility.

* **`nvcc_arch_flags` and `nvcc_arch_readable`:**
    * Functionality: Generate NVCC compiler flags related to target GPU architectures. `nvcc_arch_flags` returns the flags for compilation, while `nvcc_arch_readable` returns human-readable names for those architectures.
    * Reversing: Highly relevant. Specifying target architectures during compilation influences the generated binary code. Reverse engineers might need to know which architectures were targeted.
    * Binary/Kernel/Framework: Directly related to the binary code generation process for CUDA.
    * Input/Output: Input: CUDA Toolkit version, target architecture(s) (e.g., "Auto", "7.0", "sm_80"), and potentially detected architectures. Output: A list of NVCC flags (e.g., `['-gencode', 'arch=compute_70,code=sm_70']`) or readable names (e.g., `['sm_70']`).
    * Usage Errors: Providing invalid architecture names, conflicting architecture specifications.
    * User Path: Specifying CUDA architecture targets in the `meson.build` file.

* **Internal Helper Methods (`_break_arch_string`, `_detected_cc_from_compiler`, `_validate_nvcc_arch_args`, `_filter_cuda_arch_list`, `_nvcc_arch_flags`):**
    * Functionality: These support the main methods. Understand their individual roles in processing architecture strings, validating arguments, and filtering architecture lists.
    * Reversing:  Understanding the logic in these helpers can provide insights into how Meson determines compilation targets.
    * Binary/Kernel/Framework: Related to the details of CUDA compilation and NVIDIA's architecture naming conventions.
    * Input/Output: Analyze their inputs and expected transformations.
    * Usage Errors: Indirectly affected by errors in the main methods' inputs.
    * User Path: These are internal calls, so the user interacts with them through the public methods.

**Overall Approach:**

I'll process each method, explaining its purpose and then connect it to the user's request points. I'll focus on clarity and provide concrete examples where possible.
This Python code defines a module named `cuda` for the Meson build system. Meson is a build system generator that helps automate the process of compiling software. The `cuda` module specifically provides functionality to help manage the compilation of CUDA code, which is a parallel computing platform and programming model developed by NVIDIA.

Let's break down its functionalities:

**1. `min_driver_version(self, state, args, kwargs)`:**

* **Functionality:** This method determines the minimum required NVIDIA driver version for a given CUDA Toolkit version. It uses a lookup table (`driver_version_table`) that maps CUDA Toolkit versions to the corresponding minimum driver versions for Windows and Linux.
* **Relationship to Reversing:** While not directly a reversing tool, knowing the minimum driver version can be helpful when setting up an environment to analyze or reverse engineer a CUDA application. You need to ensure your environment meets the application's requirements.
* **Binary底层, linux, android内核及框架的知识:** This method implicitly relies on the knowledge that CUDA applications require specific driver versions to function correctly. The table itself reflects compatibility information between the CUDA user-space libraries and the kernel-level driver on Linux and Windows. Android is not explicitly mentioned in this table, suggesting this module might primarily focus on desktop/server environments.
* **逻辑推理:**
    * **假设输入:**  `cuda_version = "11.3.0"`
    * **输出:** The code iterates through `driver_version_table` and finds the entry where `'cuda_version'` (`>=11.3.0`) matches. It then returns the corresponding driver version for the host operating system (either Windows or Linux). If the host is Linux, it would return `"465.19.01"`.
* **用户或者编程常见的使用错误:**
    * Passing an incorrect or non-string argument for the CUDA Toolkit version.
    * Misunderstanding that the CUDA Toolkit components are versioned independently since CUDA 11.0, and relying on a single version number might not be precise.
* **用户操作是如何一步步的到达这里，作为调试线索:**
    1. A user writes a `meson.build` file for a project that includes CUDA code.
    2. In the `meson.build` file, the user might call the `cuda.min_driver_version()` function, passing the CUDA Toolkit version they intend to use.
    3. Meson parses the `meson.build` file and executes the `cuda.py` module.
    4. The `min_driver_version` method is called with the provided arguments.
    5. During debugging, if there's an issue with driver compatibility, a developer might trace the execution and find themselves within this method, inspecting the lookup table and the logic.

**2. `nvcc_arch_flags(self, state, args, kwargs)`:**

* **Functionality:** This method generates the appropriate NVCC (NVIDIA CUDA Compiler) flags for specifying the target GPU architectures during compilation. It takes the CUDA Toolkit version and a list of target architectures as input and returns a list of NVCC flags.
* **Relationship to Reversing:** This is highly relevant to reversing. The target architecture flags determine the specific instruction sets and features the compiled CUDA code will utilize. Reverse engineers often need to know the target architectures to understand the capabilities and limitations of the code they are analyzing. Different architectures have different instruction sets and capabilities.
* **Binary底层, linux, android内核及框架的知识:** This method directly deals with the specifics of CUDA compilation and the NVCC compiler. It understands different GPU architectures (like Fermi, Kepler, Maxwell, etc.) and how to generate the corresponding `-gencode` flags for NVCC. This is low-level knowledge about the CUDA compilation process.
* **逻辑推理:**
    * **假设输入:** `cuda_version = "11.6"`, `args = ("11.6", ["sm_70", "sm_80"])`, `kwargs = {}`
    * **输出:** The `_nvcc_arch_flags` method would be called internally. It would process the architecture list and generate NVCC flags like `['-gencode', 'arch=compute_70,code=sm_70']`, `['-gencode', 'arch=compute_80,code=sm_80']`.
* **用户或者编程常见的使用错误:**
    * Providing incorrect or misspelled architecture names.
    * Specifying architectures not supported by the given CUDA Toolkit version.
    * Not understanding the difference between compute capability and SM version.
* **用户操作是如何一步步的到达这里，作为调试线索:**
    1. A user wants to compile CUDA code for specific GPU architectures for performance or compatibility reasons.
    2. In their `meson.build` file, they call `cuda.nvcc_arch_flags()`, providing the CUDA Toolkit version and the desired architecture names (e.g., `cuda.nvcc_arch_flags(cuda_compiler, ['sm_70', 'sm_80'])`).
    3. Meson executes this line, calling the `nvcc_arch_flags` method in `cuda.py`.
    4. If the compilation fails or produces unexpected results, the developer might investigate the generated NVCC flags and trace back to this method to understand how the flags were created.

**3. `nvcc_arch_readable(self, state, args, kwargs)`:**

* **Functionality:** Similar to `nvcc_arch_flags`, but instead of generating NVCC flags, it returns human-readable names for the specified GPU architectures.
* **Relationship to Reversing:**  Provides a more user-friendly way to understand the target architectures compared to the raw NVCC flags. It can help in documenting or understanding the build configuration of a CUDA application.
* **Binary底层, linux, android内核及框架的知识:**  Relies on the same underlying knowledge of CUDA architectures as `nvcc_arch_flags`.
* **逻辑推理:**
    * **假设输入:** `cuda_version = "11.6"`, `args = ("11.6", ["7.0", "8.0"])`, `kwargs = {}`
    * **输出:** The `_nvcc_arch_flags` method would be called internally, and the `nvcc_archs_readable` list would be returned, which would be something like `['sm_70', 'sm_80']`.
* **用户或者编程常见的使用错误:**
    * Providing architecture names that don't have a standard readable representation.
* **用户操作是如何一步步的到达这里，作为调试线索:**
    1. A user wants to display or log the target GPU architectures in a human-readable format during the build process.
    2. They call `cuda.nvcc_arch_readable()` in their `meson.build` file.
    3. Meson executes this, and if there's a need to understand the output or debug issues related to architecture identification, a developer might trace the execution to this method.

**4. Internal Helper Methods (`_break_arch_string`, `_detected_cc_from_compiler`, `_validate_nvcc_arch_args`, `_filter_cuda_arch_list`, `_nvcc_arch_flags`)**

These methods support the main functionalities.

* `_break_arch_string`:  Parses a string containing a list of architectures, handling different separators.
* `_detected_cc_from_compiler`:  Extracts the detected compute capabilities from the `CudaCompiler` object.
* `_validate_nvcc_arch_args`:  Validates the arguments passed to `nvcc_arch_flags` and `nvcc_arch_readable`.
* `_filter_cuda_arch_list`:  Filters a list of CUDA architectures based on minimum and maximum limits.
* `_nvcc_arch_flags`:  The core logic for generating NVCC architecture flags based on the CUDA version and target architectures. This method contains detailed logic mapping CUDA versions to supported architectures and generating the appropriate `-gencode` flags.

**Relationship to Reversing (Examples):**

* **Identifying Target Architectures:** A reverse engineer examining a compiled CUDA binary can use tools to inspect the embedded PTX (Parallel Thread Execution) code. By comparing the architectures present in the binary with the output of `cuda.nvcc_arch_readable` for different architecture inputs, they can infer which architectures the developer targeted during compilation.
* **Understanding Optimization Levels:** Different GPU architectures have different performance characteristics. Knowing the target architecture helps in understanding the optimization strategies the developer might have employed.
* **Identifying Supported Hardware:**  If a reverse engineer finds specific architecture flags, they can determine the minimum hardware requirements for running the application.

**Binary底层, linux, android内核及框架的知识 (Examples):**

* **`-gencode` flags:** The generation of `-gencode arch=compute_XX,code=sm_YY` flags directly interacts with the NVCC compiler's understanding of how to produce binary code for different GPU architectures. `compute_XX` refers to the virtual architecture, while `sm_YY` refers to the specific Streaming Multiprocessor architecture.
* **Driver Compatibility:** The `min_driver_version` function highlights the dependency between the CUDA user-space libraries and the kernel-level driver. This is a fundamental concept in how hardware acceleration works on Linux and other operating systems.
* **GPU Architecture Naming Conventions:** The code understands NVIDIA's naming conventions for different GPU architectures (Fermi, Kepler, Maxwell, etc.) and their corresponding compute capabilities.

**Common User Errors (Examples):**

* **Typos in Architecture Names:**  A user might type "sm_75" instead of "sm_70", leading to compilation errors or unexpected behavior.
* **Specifying Incompatible Architectures:** Trying to compile for an architecture not supported by the installed CUDA Toolkit version will lead to errors.
* **Misunderstanding "Auto":**  The "Auto" option relies on the detected GPU on the build machine. If the user intends to target a specific architecture different from the build machine, this can lead to incorrect flags.

**User Operation to Reach Here (Debugging Scenario):**

Imagine a developer is building a Frida gadget (a dynamic library injected into a process) that uses CUDA.

1. The developer has a `meson.build` file that defines how to build the Frida gadget, including the CUDA parts.
2. In the `meson.build` file, they might use the `cuda` module to determine the minimum driver version or to set the NVCC architecture flags. For example:
   ```python
   cuda_mod = import('cuda')
   cuda_version = '11.6' # Or get it from the environment
   min_driver = cuda_mod.min_driver_version(cuda_version)
   print('Minimum CUDA Driver:', min_driver)

   cuda_compiler = find_program('nvcc') # Or however the CUDA compiler is obtained
   arch_flags = cuda_mod.nvcc_arch_flags(cuda_compiler, ['sm_70', 'sm_80'])
   cuda_lib = shared_library('my_cuda_lib', 'my_cuda_code.cu',
                             dependencies: ...,
                             cuda_args: arch_flags)
   ```
3. When the developer runs `meson build`, Meson interprets the `meson.build` file and executes the Python code.
4. If there's an issue, like the CUDA compilation failing because of incorrect architecture flags, the developer might start debugging.
5. They might examine the generated build commands and see the NVCC flags.
6. To understand where these flags came from, they might look at the Meson logs or even step through the `meson.build` execution (if using a debugger with Meson).
7. This would lead them to the `cuda.py` file and specifically to the `nvcc_arch_flags` method, allowing them to inspect the logic and the inputs provided.

In summary, this `cuda.py` module in Frida's build system provides essential functionalities for managing CUDA compilation, focusing on determining driver compatibility and generating appropriate compiler flags for targeting specific GPU architectures. This is crucial for ensuring CUDA applications built with Frida are compatible with the intended hardware and environment. Understanding this module is valuable for reverse engineers who analyze CUDA-based applications.

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/modules/cuda.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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