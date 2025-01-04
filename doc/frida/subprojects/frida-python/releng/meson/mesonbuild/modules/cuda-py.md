Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding: Context is Key**

The first step is to recognize the context:

* **File Path:** `frida/subprojects/frida-python/releng/meson/mesonbuild/modules/cuda.py`  This immediately tells us it's part of Frida (a dynamic instrumentation toolkit), specifically the Python bindings, and is related to the Meson build system's CUDA module.
* **Copyright & License:**  `SPDX-License-Identifier: Apache-2.0` and `Copyright 2017 The Meson development team` indicate open-source and provide ownership information.
* **Imports:** The imports are crucial for understanding dependencies and functionality. `mesonlib`, `compilers.cuda`, `interpreter.*`, and `NewExtensionModule`, `ModuleInfo` point to Meson's internal structure and how this module interacts within it. `typing` and `typing_extensions` are for type hinting, which helps with code clarity and maintainability but isn't directly functional for the user. `re` is for regular expressions, hinting at string manipulation.

**2. Identifying the Core Class: `CudaModule`**

The `CudaModule` class is the central element. Its inheritance from `NewExtensionModule` suggests it's a Meson module designed to extend Meson's capabilities related to CUDA.

**3. Analyzing Methods: Functionality Breakdown**

The next step is to go through each method within `CudaModule` and understand its purpose:

* **`__init__`:**  Standard constructor, initializes the module and registers its methods. The `self.methods.update(...)` line is key – it lists the callable functions provided by this module.
* **`min_driver_version`:**  This looks up the minimum required NVIDIA driver version for a given CUDA Toolkit version. The `driver_version_table` is the heart of this function. The logic involves comparing the input CUDA version with the table and returning the corresponding driver version for the host OS.
* **`nvcc_arch_flags`:**  This function generates the appropriate compiler flags for the `nvcc` (NVIDIA CUDA Compiler) based on the target GPU architectures. It handles different ways of specifying architectures (like "Auto", "Common", specific SM versions).
* **`nvcc_arch_readable`:**  Similar to `nvcc_arch_flags`, but returns a more human-readable representation of the target architectures.
* **`_break_arch_string`:** A helper function to split architecture strings.
* **`_detected_cc_from_compiler`:** Extracts the detected compute capability from a `CudaCompiler` object.
* **`_validate_nvcc_arch_args`:**  Validates the arguments passed to `nvcc_arch_flags` and `nvcc_arch_readable`.
* **`_filter_cuda_arch_list`:** Filters a list of CUDA architectures based on minimum and maximum bounds.
* **`_nvcc_arch_flags`:**  This is the core logic for generating the NVCC flags. It contains a large conditional block based on the CUDA Toolkit version and defines lists of known, common, and all GPU architectures. It then uses this information to generate the `-gencode` flags for `nvcc`.
* **`initialize`:**  A function outside the class, likely called by Meson to instantiate the `CudaModule`.

**4. Connecting to Reverse Engineering, Low-Level Concepts, and Reasoning**

Now, we need to connect these functions to the prompt's specific points:

* **Reverse Engineering:**  Consider how CUDA is used in reverse engineering. Frida often interacts with processes at runtime. Knowing the target GPU architecture is important when injecting code or understanding how a CUDA application is working. The `nvcc_arch_flags` function directly relates to this by ensuring the generated code is compatible with the target GPU.
* **Binary/Low-Level:** CUDA involves compiling code to run on the GPU. The `-gencode` flags directly influence the binary code generated for different Streaming Multiprocessor (SM) architectures. The function deals with specific SM versions (e.g., "sm_80").
* **Linux/Android Kernel/Framework:** The `min_driver_version` function differentiates between Windows and Linux driver versions. While not directly interacting with the kernel *in this specific code*, it highlights the dependency on the underlying OS and driver. In the context of Android (which is a Linux-based system), this is relevant when targeting Frida on Android devices.
* **Logical Reasoning:** The `_nvcc_arch_flags` function performs complex logical reasoning based on CUDA version and desired architectures. The `if version_compare(...)` statements are the core of this logic. We can provide input (CUDA version, target architectures) and trace the output (the generated flags).

**5. Identifying Potential User Errors and Usage Scenarios**

Think about how a user might interact with this module in a `meson.build` file:

* **Incorrect CUDA Version:** Providing a wrong or misspelled CUDA Toolkit version to `min_driver_version`.
* **Invalid Architecture Strings:** Providing malformed or unknown architecture names to `nvcc_arch_flags`.
* **Misunderstanding "Auto":** Assuming "Auto" will always detect the desired architectures correctly.

**6. Tracing User Interaction**

Consider how a user ends up using this code:

1. **Developing a project that uses CUDA.**
2. **Choosing Meson as the build system.**
3. **Needing to compile CUDA code as part of their project.**
4. **Using Meson's built-in CUDA support or potentially relying on a custom module like this one (within the Frida context).**
5. **Calling the functions provided by this module in their `meson.build` file.**

**7. Structuring the Output**

Finally, organize the findings into the requested categories: functionality, reverse engineering relevance, low-level details, logical reasoning, user errors, and usage steps. Use clear and concise language, providing concrete examples where possible. The initial breakdown of methods provides a good structure for explaining functionality.

**Self-Correction/Refinement During the Process:**

* **Initially, I might focus too much on the Frida context.**  While important, remember the code itself is a Meson module. The Frida context enhances the relevance of certain functionalities (like the importance of architecture flags in dynamic instrumentation).
* **Ensure examples are relevant.** Don't just provide generic examples; tailor them to the context of CUDA and build systems.
* **Double-check the code for subtleties.** For example, the different ways architectures can be specified ("All", "Common", specific SMs) and how the code handles these variations.

By following these steps, we can systematically analyze the provided code and generate a comprehensive and accurate explanation.
This Python code defines a Meson build system module named `cuda`. Meson is a build system generator that aims for speed and user-friendliness. This module specifically provides functionality related to working with NVIDIA's CUDA toolkit within the Meson build process.

Here's a breakdown of its functionalities:

**1. Determining Minimum CUDA Driver Version:**

* **Function:** `min_driver_version(self, state: 'ModuleState', args: T.List[TYPE_var], kwargs: T.Dict[str, T.Any]) -> str`
* **Functionality:** Given a CUDA Toolkit version string, this function returns the minimum required NVIDIA driver version for that toolkit version on the host operating system (Windows or Linux). It uses a hardcoded table (`driver_version_table`) to look up this information.
* **Relation to Reverse Engineering:** While not directly a reverse engineering *method*, knowing the minimum driver version can be crucial when setting up an environment for reverse engineering CUDA applications. If you're analyzing a CUDA application, ensuring you have a compatible driver is a fundamental prerequisite.
* **Binary底层, Linux, Android 内核及框架的知识:**
    * **Binary 底层:** CUDA drivers interact directly with the GPU hardware at a very low level. The driver version dictates which CUDA features are supported by the hardware.
    * **Linux:** The function explicitly checks `state.environment.machines.host.system` to determine if the host OS is Linux and selects the corresponding driver version from the table. This acknowledges the OS-specific nature of drivers.
* **逻辑推理 (Hypothetical Input/Output):**
    * **Input:**  `"11.5.0"` (CUDA Toolkit version)
    * **Output (on Linux):** `"495.29.05"`
    * **Output (on Windows):** `"496.04"`
* **用户或编程常见的使用错误:**
    * **Error:** Providing an incorrect or malformed CUDA Toolkit version string (e.g., `"11.5"` instead of `"11.5.0"`). This would lead to the function not finding a match in the `driver_version_table` and returning `"unknown"`.
* **用户操作如何一步步的到达这里 (调试线索):**
    1. A user is writing a `meson.build` file for a project that uses CUDA.
    2. They want to ensure that users of their project have a compatible NVIDIA driver.
    3. They use the `cuda.min_driver_version()` function in their `meson.build` file, passing the required CUDA Toolkit version as an argument.
    4. Meson, during its build system generation phase, executes this Python code. If there's an issue with the provided CUDA version, they might get an unexpected result or an error message originating from this function.

**2. Generating NVCC Architecture Flags:**

* **Functions:**
    * `nvcc_arch_flags(self, state: 'ModuleState', args: T.Tuple[T.Union[CudaCompiler, str], T.List[str]], kwargs: ArchFlagsKwargs) -> T.List[str]`
    * `nvcc_arch_readable(self, state: 'ModuleState', args: T.Tuple[T.Union[CudaCompiler, str], T.List[str]], kwargs: ArchFlagsKwargs) -> T.List[str]`
    * `_nvcc_arch_flags(self, cuda_version: str, cuda_arch_list: AutoArch, detected: T.List[str]) -> T.Tuple[T.List[str], T.List[str]]` (internal helper)
* **Functionality:** These functions are responsible for generating the correct `-gencode` flags for the `nvcc` compiler based on the target GPU architectures.
    * `nvcc_arch_flags` returns the raw compiler flags (e.g., `'-gencode', 'arch=compute_80,code=sm_80'`).
    * `nvcc_arch_readable` returns a more human-readable representation of the target architectures (e.g., `'sm_80'`).
    * They take the CUDA Toolkit version and a list of target architectures as input. The architectures can be specified in different ways:
        * Specific SM versions (e.g., `"7.5"`)
        * Architecture names (e.g., `"Turing"`)
        * Special keywords like `"All"`, `"Common"`, `"Auto"`.
* **Relation to Reverse Engineering:** This is highly relevant to reverse engineering CUDA applications. When disassembling or analyzing CUDA binaries (kernels), it's crucial to know the target GPU architectures. The `-gencode` flags determine which instruction sets and features are included in the compiled binary. Knowing these flags helps understand the intended target hardware and the potential capabilities of the code.
* **Binary 底层, Linux, Android 内核及框架的知识:**
    * **Binary 底层:** The `-gencode` flags directly influence the machine code generated by `nvcc`. Different GPU architectures support different instruction sets and features. Understanding these flags is essential for analyzing the raw binary instructions.
    * **Linux/Android:** While the code itself doesn't directly interact with the kernel, the concept of targeting specific GPU architectures is relevant on both Linux and Android, where CUDA is used. On Android, the GPU hardware and driver stack are a crucial part of the framework.
* **逻辑推理 (Hypothetical Input/Output):**
    * **Input (nvcc_arch_flags):** `cuda_version="11.0"`, `arch_list=["Auto"]`
    * **Output:**  A list of `-gencode` flags based on the detected GPU on the build machine (the logic for "Auto" involves detecting the available GPU). Let's assume the detected GPU is Ampere. The output might be: `['-gencode', 'arch=compute_80,code=sm_80']`
    * **Input (nvcc_arch_readable):** `cuda_version="10.2"`, `arch_list=["Turing", "Volta"]`
    * **Output:** `['sm_75', 'sm_70']`
* **用户或编程常见的使用错误:**
    * **Error:** Providing an invalid architecture name (e.g., `"SuperFastGPU"`). The `_nvcc_arch_flags` function has a lookup table for known architectures, and providing an unknown name will raise an `InvalidArguments` exception.
    * **Error:** Misunderstanding the meaning of `"Auto"`. If no CUDA-capable GPU is detected on the build machine, `"Auto"` might resolve to a common set of architectures instead of the one they intended for their target platform.
    * **Error:** Incorrectly using `"All"`, `"Common"`, or `"Auto"` when also specifying other architectures in the `arch_list`. The code explicitly checks for this and raises an `InvalidArguments` exception.
* **用户操作如何一步步的到达这里 (调试线索):**
    1. A user is configuring how their CUDA code should be compiled within their `meson.build` file.
    2. They use the `cuda.nvcc_arch_flags()` or `cuda.nvcc_arch_readable()` functions to generate the necessary compiler flags.
    3. They might pass a specific architecture list or use the `"Auto"` option.
    4. If the compilation fails or produces unexpected results, they might need to debug the generated architecture flags. Examining the output of these functions helps understand which GPU architectures are being targeted.

**In Summary, the `cuda.py` module in Frida's build system provides essential functionalities for managing CUDA compilation within the Meson build process. It helps ensure that the correct minimum driver version is known and that CUDA code is compiled for the intended GPU architectures. This is directly relevant to reverse engineering CUDA applications as it provides crucial information about the target environment and the compiled binary structure.**

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/modules/cuda.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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