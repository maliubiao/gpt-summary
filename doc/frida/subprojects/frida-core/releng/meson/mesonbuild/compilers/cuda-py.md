Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Initial Understanding of the Context:**

The first and most crucial step is to understand *what* this code is. The prompt clearly states: "这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/compilers/cuda.py的fridaDynamic instrumentation tool的源代码文件". This tells us several key things:

* **Location:**  It's within the Frida project, specifically in the build system (Meson) related to compilers, and even more specifically for the CUDA language.
* **Purpose:** It's related to *compiling* CUDA code within the Frida build process. This immediately suggests functionality around handling compiler flags, setting up the compilation environment, and interacting with the CUDA compiler (NVCC).
* **Language:** The code itself is Python.

**2. Skimming for Key Structures and Patterns:**

Next, a quick skim of the code reveals important elements:

* **Imports:** Libraries like `enum`, `os.path`, `string`, and crucially, elements from `..mesonlib` and `.compilers`. These imports hint at the code's dependencies and the types of operations it performs (string manipulation, path handling, interacting with Meson's core functionalities).
* **Constants/Data Structures:**  `cuda_optimization_args` and `cuda_debug_args` are dictionaries mapping optimization and debug levels to compiler flags. This immediately points to the code's ability to configure the compilation process. The large dictionaries `_FLAG_PASSTHRU_NOARGS`, `_FLAG_LONG2SHORT_WITHARGS`, and `_FLAG_SHORT2LONG_WITHARGS` strongly suggest that the code is involved in translating or mapping compiler flags.
* **Classes:** The `CudaCompiler` class inheriting from `Compiler` is the central element. This reinforces that the code is defining a specific compiler implementation for CUDA within Meson.
* **Methods:**  The methods within `CudaCompiler` provide clues about its functions. Names like `_shield_nvcc_list_arg`, `_merge_flags`, `_to_host_flags`, `sanity_check`, and `has_header_symbol` are indicative of specific actions the compiler class can perform.

**3. Deep Dive into Key Methods and Logic:**

Now, focus on the most significant methods and the logic within them:

* **`__init__`:**  The constructor initializes the `CudaCompiler` object, importantly taking a `host_compiler` as an argument. This signals that the CUDA compilation process is tied to a host compiler (likely for CPU code).
* **Flag Handling (`_shield_nvcc_list_arg`, `_merge_flags`, `_to_host_flags`):** These methods are clearly designed to manage and transform compiler flags. The complex logic in `_shield_nvcc_list_arg` dealing with commas and quoting is a key detail showing how the code handles NVCC's specific flag parsing rules. `_to_host_flags` translates generic compiler flags to NVCC-specific ones, and importantly, it interacts with the `host_compiler`. This is crucial for understanding the interaction between CUDA and CPU compilation.
* **`sanity_check`:**  This method performs a basic compilation and execution test to ensure the CUDA compiler is working correctly. The code it compiles (`sanitycheckcuda.cu`) and the checks it performs (checking for CUDA devices) are revealing. The use of `--run` and `--run-args` is specific to NVCC for running binaries with the correct environment.
* **`has_header_symbol`:** This method checks if a given header file defines a specific symbol. This is a standard compiler utility function for checking library availability.

**4. Connecting to the Prompt's Questions:**

With a solid understanding of the code, address the specific questions in the prompt:

* **Functionality:**  Summarize the main purposes of the code based on the analysis of its structure and methods.
* **Relationship to Reverse Engineering:** Consider how CUDA compilation might be relevant to reverse engineering. CUDA is used for GPU acceleration, often in computationally intensive tasks. Reverse engineering software using CUDA might involve understanding the compiled CUDA kernels.
* **Binary, Linux, Android Kernel/Framework:** Think about how CUDA and its compilation process relate to these concepts. CUDA involves low-level interaction with the GPU. It runs on Linux and Android, requiring kernel drivers and potentially interacting with frameworks that manage GPU resources.
* **Logical Reasoning:** Identify any explicit conditional logic or decision-making within the code (like the handling of different optimization levels). Consider potential inputs (compiler flags, source code) and outputs (compiled binaries, error messages).
* **User Errors:** Imagine common mistakes developers might make when using CUDA or the build system, which this code might help mitigate or where errors might still occur.
* **User Operations and Debugging:**  Trace back how a user might end up in this part of the Frida build system – likely by trying to build or use a Frida component that involves CUDA.

**5. Structuring the Answer:**

Finally, organize the findings into a clear and structured response, addressing each point of the prompt systematically. Use examples where possible to illustrate the concepts.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  "This is just about compiling CUDA."  **Correction:** While compilation is the core, the code also handles flag translation, sanity checks, and interaction with the host compiler, making it more complex.
* **Overlooking details:**  Initially, I might skim over the specifics of the flag mapping dictionaries. **Correction:** Recognizing the importance of these dictionaries in understanding how flags are translated and the nuances of NVCC is crucial.
* **Not connecting to reverse engineering:**  I might initially focus solely on the build process. **Correction:**  Actively thinking about the *output* of this process (compiled CUDA code) and its relevance to reverse engineering is necessary to answer that part of the prompt.
* **Vague explanations:**  Simply stating "handles compiler flags" is not enough. **Correction:** Providing details about *how* it handles them (translation, shielding, merging) is important.

By following this structured thought process, moving from high-level understanding to detailed analysis and then connecting back to the specific questions, a comprehensive and accurate answer can be generated.
这是 `frida/subprojects/frida-core/releng/meson/mesonbuild/compilers/cuda.py` 文件的第一部分，它定义了 Frida 项目中用于处理 CUDA 编译器（通常是 NVCC）的类 `CudaCompiler`。 它的主要功能是：

**核心功能:**

1. **提供 CUDA 编译器的 Meson 接口:**  `CudaCompiler` 类继承自 Meson 的 `Compiler` 基类，使得 Meson 构建系统能够理解和使用 CUDA 编译器。这包括定义 CUDA 语言的标识符 (`language = 'cuda'`) 和编译器 ID (`id = 'nvcc'`)。

2. **处理 CUDA 编译器特定的命令行参数:**  代码中定义了大量的字典 (`_FLAG_PASSTHRU_NOARGS`, `_FLAG_LONG2SHORT_WITHARGS`, `_FLAG_SHORT2LONG_WITHARGS`) 来映射和管理 NVCC 编译器的各种命令行选项。这允许 Meson 以更通用的方式指定编译选项，然后由 `CudaCompiler` 转换为 NVCC 理解的格式。

3. **转换通用编译器标志为 NVCC 标志:**  `_to_host_flags` 方法是核心，它负责将 Meson 或通用编译器的标志转换为 NVCC 的特定标志。由于 NVCC 的标志语法和行为与 GCC 等标准编译器略有不同，这个转换是必要的。例如，它处理逗号分隔的列表参数，以及将 `-ffast-math` 转换为 NVCC 的 `-use_fast_math`。

4. **执行 CUDA 编译器的健全性检查:** `sanity_check` 方法会编译一个简单的 CUDA 程序并尝试运行它，以确保 CUDA 编译器能够正常工作。这个过程也用于检测本地构建的 GPU 架构。

5. **与主机编译器集成:**  `CudaCompiler` 实例需要一个 `host_compiler` 参数，这通常是 C 或 C++ 编译器。 CUDA 代码通常需要与 CPU 代码一起编译和链接，因此与主机编译器的集成至关重要。  例如，它使用主机编译器的警告参数 (`warn_args`)，并使用 `-Xcompiler=` 将某些标志传递给主机编译器。

6. **管理优化和调试标志:** `cuda_optimization_args` 和 `cuda_debug_args` 字典定义了不同优化级别和调试模式下应使用的 NVCC 标志。

**与逆向方法的关联和举例:**

* **了解底层 CUDA 代码编译方式:** 逆向工程师可能需要理解目标软件中使用的 CUDA 代码是如何被编译的，包括使用了哪些编译器选项、优化级别等。`CudaCompiler` 提供了关于 NVCC 常用选项和其与通用编译器选项之间映射关系的线索。
    * **举例:** 假设逆向一个使用了 CUDA 进行加速的图像处理程序，逆向工程师可能会关注该程序使用了哪些 CUDA kernel。通过分析构建脚本（如果可以获取到），并结合 `CudaCompiler` 中定义的优化标志，例如 `-O3` 对应 `cuda_optimization_args['3']`，可以推断出该程序可能使用了最高级别的优化，这可能会使逆向分析变得更复杂。

* **理解混淆和反调试技术:** 一些混淆技术可能会利用编译器特定的特性或行为。了解 CUDA 编译器的行为可以帮助逆向工程师识别和绕过这些技术。
    * **举例:**  某些反调试技术可能会检查特定的编译标志是否存在。如果逆向工程师知道目标程序使用了 NVCC 编译，并且能够找到构建脚本或类似信息，就可以查看是否使用了 `-debug` 或 `-G` 等调试相关的标志，从而判断程序是否开启了调试信息，或者反调试技术是否尝试阻止调试。

**涉及到二进制底层、Linux、Android 内核及框架的知识和举例:**

* **二进制目标文件格式:** CUDA 编译器会生成特定的二进制目标文件（例如 `.o` 或 `.obj`），这些文件最终会被链接成可执行文件或库。了解这些二进制文件的结构（例如 ELF 或 PE 格式）有助于逆向分析。
    * **举例:**  在 Linux 或 Android 系统上，CUDA 编译器生成的目标文件通常是 ELF 格式。逆向工程师需要了解 ELF 文件的结构，例如 section 和 symbol table，才能分析编译后的 CUDA 代码。

* **CUDA Runtime 和 Driver:**  编译后的 CUDA 代码依赖于 CUDA Runtime 和 Driver。了解这些组件在 Linux 和 Android 系统上的工作方式，以及它们与内核的交互，对于理解 CUDA 程序的行为至关重要。
    * **举例:**  `sanity_check` 方法中包含了 `#include <cuda_runtime.h>`，这表明编译后的代码会链接到 CUDA Runtime 库。逆向工程师需要了解 CUDA Runtime 提供的 API（例如 `cudaMalloc`, `cudaMemcpy`, kernel launch 等）以及它们在底层如何与 GPU Driver 交互。

* **Android 框架中的 CUDA 支持:**  在 Android 上使用 CUDA 需要考虑 Android 特定的框架和权限。了解 Android 如何管理 GPU 资源以及 CUDA 程序如何在 Android 应用程序中运行，是进行逆向分析的重要方面。
    * **举例:**  在 Android 上，访问 GPU 通常需要特定的权限。如果逆向分析一个 Android 应用，发现它使用了 CUDA，就需要考虑该应用是否声明了相关的 GPU 访问权限，以及它如何与 Android 的图形系统进行交互。

**逻辑推理、假设输入与输出:**

* **假设输入:** 一个包含以下 CUDA 源代码的文件 `my_kernel.cu`:
  ```c++
  __global__ void add(int *a, int *b, int *c) {
      int i = blockIdx.x * blockDim.x + threadIdx.x;
      c[i] = a[i] + b[i];
  }
  ```
  以及 Meson 构建系统中调用 CUDA 编译器的指令，例如设置优化级别为 "2"。
* **输出:**  `_to_host_flags` 方法会根据优化级别 "2"，将通用的优化标志转换为 NVCC 的 `['-O2', '-lineinfo']`。当实际调用 NVCC 编译器时，命令行参数会包含这些标志。

**用户或编程常见的使用错误和举例:**

* **未安装 CUDA Toolkit:** 如果用户的系统上没有安装 CUDA Toolkit，`sanity_check` 方法将会失败，因为找不到 `nvcc` 编译器。
    * **错误信息示例:**  可能类似于 "Compiler `nvcc` not found"。

* **CUDA 版本不兼容:** 如果系统中安装的 CUDA Toolkit 版本与 Frida 期望的版本不兼容，可能会导致编译错误或运行时错误。
    * **错误信息示例:**  可能包含与 CUDA Runtime 或 Driver 版本相关的错误。

* **传递了错误的编译器标志:**  如果用户在 Meson 构建系统中传递了 CUDA 编译器不支持的标志，或者与 NVCC 语法不符的标志，`_to_host_flags` 方法可能无法正确转换，导致编译失败。
    * **错误信息示例:**  NVCC 可能会输出关于未知或无效命令行选项的错误信息。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试构建或重新配置 Frida:** 用户可能运行了 `meson setup _build` 或 `ninja` 命令来构建 Frida。

2. **Meson 解析 `meson.build` 文件:** Meson 会读取项目根目录或其他相关目录下的 `meson.build` 文件，这些文件描述了项目的构建过程，包括需要编译哪些源文件以及使用哪些编译器。

3. **检测到 CUDA 源文件:** 如果 `meson.build` 文件中声明了需要编译 CUDA 源文件（例如 `.cu` 文件），Meson 会尝试找到并使用 CUDA 编译器。

4. **调用 `CudaCompiler` 类:** Meson 会实例化 `CudaCompiler` 类（如果尚未实例化），该类负责处理 CUDA 编译器的相关操作。

5. **执行 `sanity_check` (首次配置时):**  首次配置构建系统时，Meson 可能会调用 `CudaCompiler` 的 `sanity_check` 方法来验证 CUDA 编译器是否可用且功能正常。如果 `sanity_check` 失败，会提示用户 CUDA 编译器存在问题。

6. **编译 CUDA 源文件:** 当实际编译 CUDA 源文件时，Meson 会调用 `CudaCompiler` 的方法，例如使用 `_to_host_flags` 来准备 NVCC 的命令行参数，然后调用 NVCC 编译器执行编译。

**归纳一下它的功能:**

总而言之，`frida/subprojects/frida-core/releng/meson/mesonbuild/compilers/cuda.py` 文件的主要功能是 **为 Frida 项目提供了一个 Meson 构建系统可以理解和使用的 CUDA 编译器接口。** 它负责处理 NVCC 编译器的特定命令行选项，将通用的编译器标志转换为 NVCC 理解的格式，执行编译器的健全性检查，并与主机编译器集成，从而使得 Frida 能够顺利地编译和构建包含 CUDA 代码的组件。 这对于 Frida 动态插桩工具来说至关重要，因为它可能需要与目标进程中运行的 CUDA 代码进行交互或监控。

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/compilers/cuda.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2017 The Meson development team

from __future__ import annotations

import enum
import os.path
import string
import typing as T

from .. import coredata
from .. import mlog
from ..mesonlib import (
    EnvironmentException, Popen_safe,
    is_windows, LibType, OptionKey, version_compare,
)
from .compilers import Compiler

if T.TYPE_CHECKING:
    from .compilers import CompileCheckMode
    from ..build import BuildTarget
    from ..coredata import MutableKeyedOptionDictType, KeyedOptionDictType
    from ..dependencies import Dependency
    from ..environment import Environment  # noqa: F401
    from ..envconfig import MachineInfo
    from ..linkers.linkers import DynamicLinker
    from ..mesonlib import MachineChoice


cuda_optimization_args: T.Dict[str, T.List[str]] = {
    'plain': [],
    '0': ['-G'],
    'g': ['-O0'],
    '1': ['-O1'],
    '2': ['-O2', '-lineinfo'],
    '3': ['-O3'],
    's': ['-O3']
}

cuda_debug_args: T.Dict[bool, T.List[str]] = {
    False: [],
    True: ['-g']
}


class _Phase(enum.Enum):

    COMPILER = 'compiler'
    LINKER = 'linker'


class CudaCompiler(Compiler):

    LINKER_PREFIX = '-Xlinker='
    language = 'cuda'

    # NVCC flags taking no arguments.
    _FLAG_PASSTHRU_NOARGS = {
        # NVCC --long-option,                   NVCC -short-option              CUDA Toolkit 11.2.1 Reference
        '--objdir-as-tempdir',                  '-objtemp',                     # 4.2.1.2
        '--generate-dependency-targets',        '-MP',                          # 4.2.1.12
        '--allow-unsupported-compiler',         '-allow-unsupported-compiler',  # 4.2.1.14
        '--link',                                                               # 4.2.2.1
        '--lib',                                '-lib',                         # 4.2.2.2
        '--device-link',                        '-dlink',                       # 4.2.2.3
        '--device-c',                           '-dc',                          # 4.2.2.4
        '--device-w',                           '-dw',                          # 4.2.2.5
        '--cuda',                               '-cuda',                        # 4.2.2.6
        '--compile',                            '-c',                           # 4.2.2.7
        '--fatbin',                             '-fatbin',                      # 4.2.2.8
        '--cubin',                              '-cubin',                       # 4.2.2.9
        '--ptx',                                '-ptx',                         # 4.2.2.10
        '--preprocess',                         '-E',                           # 4.2.2.11
        '--generate-dependencies',              '-M',                           # 4.2.2.12
        '--generate-nonsystem-dependencies',    '-MM',                          # 4.2.2.13
        '--generate-dependencies-with-compile', '-MD',                          # 4.2.2.14
        '--generate-nonsystem-dependencies-with-compile', '-MMD',               # 4.2.2.15
        '--run',                                                                # 4.2.2.16
        '--profile',                            '-pg',                          # 4.2.3.1
        '--debug',                              '-g',                           # 4.2.3.2
        '--device-debug',                       '-G',                           # 4.2.3.3
        '--extensible-whole-program',           '-ewp',                         # 4.2.3.4
        '--generate-line-info',                 '-lineinfo',                    # 4.2.3.5
        '--dlink-time-opt',                     '-dlto',                        # 4.2.3.8
        '--no-exceptions',                      '-noeh',                        # 4.2.3.11
        '--shared',                             '-shared',                      # 4.2.3.12
        '--no-host-device-initializer-list',    '-nohdinitlist',                # 4.2.3.15
        '--expt-relaxed-constexpr',             '-expt-relaxed-constexpr',      # 4.2.3.16
        '--extended-lambda',                    '-extended-lambda',             # 4.2.3.17
        '--expt-extended-lambda',               '-expt-extended-lambda',        # 4.2.3.18
        '--m32',                                '-m32',                         # 4.2.3.20
        '--m64',                                '-m64',                         # 4.2.3.21
        '--forward-unknown-to-host-compiler',   '-forward-unknown-to-host-compiler', # 4.2.5.1
        '--forward-unknown-to-host-linker',     '-forward-unknown-to-host-linker',   # 4.2.5.2
        '--dont-use-profile',                   '-noprof',                      # 4.2.5.3
        '--dryrun',                             '-dryrun',                      # 4.2.5.5
        '--verbose',                            '-v',                           # 4.2.5.6
        '--keep',                               '-keep',                        # 4.2.5.7
        '--save-temps',                         '-save-temps',                  # 4.2.5.9
        '--clean-targets',                      '-clean',                       # 4.2.5.10
        '--no-align-double',                                                    # 4.2.5.16
        '--no-device-link',                     '-nodlink',                     # 4.2.5.17
        '--allow-unsupported-compiler',         '-allow-unsupported-compiler',  # 4.2.5.18
        '--use_fast_math',                      '-use_fast_math',               # 4.2.7.7
        '--extra-device-vectorization',         '-extra-device-vectorization',  # 4.2.7.12
        '--compile-as-tools-patch',             '-astoolspatch',                # 4.2.7.13
        '--keep-device-functions',              '-keep-device-functions',       # 4.2.7.14
        '--disable-warnings',                   '-w',                           # 4.2.8.1
        '--source-in-ptx',                      '-src-in-ptx',                  # 4.2.8.2
        '--restrict',                           '-restrict',                    # 4.2.8.3
        '--Wno-deprecated-gpu-targets',         '-Wno-deprecated-gpu-targets',  # 4.2.8.4
        '--Wno-deprecated-declarations',        '-Wno-deprecated-declarations', # 4.2.8.5
        '--Wreorder',                           '-Wreorder',                    # 4.2.8.6
        '--Wdefault-stream-launch',             '-Wdefault-stream-launch',      # 4.2.8.7
        '--Wext-lambda-captures-this',          '-Wext-lambda-captures-this',   # 4.2.8.8
        '--display-error-number',               '-err-no',                      # 4.2.8.10
        '--resource-usage',                     '-res-usage',                   # 4.2.8.14
        '--help',                               '-h',                           # 4.2.8.15
        '--version',                            '-V',                           # 4.2.8.16
        '--list-gpu-code',                      '-code-ls',                     # 4.2.8.20
        '--list-gpu-arch',                      '-arch-ls',                     # 4.2.8.21
    }
    # Dictionary of NVCC flags taking either one argument or a comma-separated list.
    # Maps --long to -short options, because the short options are more GCC-like.
    _FLAG_LONG2SHORT_WITHARGS = {
        '--output-file':                        '-o',                           # 4.2.1.1
        '--pre-include':                        '-include',                     # 4.2.1.3
        '--library':                            '-l',                           # 4.2.1.4
        '--define-macro':                       '-D',                           # 4.2.1.5
        '--undefine-macro':                     '-U',                           # 4.2.1.6
        '--include-path':                       '-I',                           # 4.2.1.7
        '--system-include':                     '-isystem',                     # 4.2.1.8
        '--library-path':                       '-L',                           # 4.2.1.9
        '--output-directory':                   '-odir',                        # 4.2.1.10
        '--dependency-output':                  '-MF',                          # 4.2.1.11
        '--compiler-bindir':                    '-ccbin',                       # 4.2.1.13
        '--archiver-binary':                    '-arbin',                       # 4.2.1.15
        '--cudart':                             '-cudart',                      # 4.2.1.16
        '--cudadevrt':                          '-cudadevrt',                   # 4.2.1.17
        '--libdevice-directory':                '-ldir',                        # 4.2.1.18
        '--target-directory':                   '-target-dir',                  # 4.2.1.19
        '--optimization-info':                  '-opt-info',                    # 4.2.3.6
        '--optimize':                           '-O',                           # 4.2.3.7
        '--ftemplate-backtrace-limit':          '-ftemplate-backtrace-limit',   # 4.2.3.9
        '--ftemplate-depth':                    '-ftemplate-depth',             # 4.2.3.10
        '--x':                                  '-x',                           # 4.2.3.13
        '--std':                                '-std',                         # 4.2.3.14
        '--machine':                            '-m',                           # 4.2.3.19
        '--compiler-options':                   '-Xcompiler',                   # 4.2.4.1
        '--linker-options':                     '-Xlinker',                     # 4.2.4.2
        '--archive-options':                    '-Xarchive',                    # 4.2.4.3
        '--ptxas-options':                      '-Xptxas',                      # 4.2.4.4
        '--nvlink-options':                     '-Xnvlink',                     # 4.2.4.5
        '--threads':                            '-t',                           # 4.2.5.4
        '--keep-dir':                           '-keep-dir',                    # 4.2.5.8
        '--run-args':                           '-run-args',                    # 4.2.5.11
        '--input-drive-prefix':                 '-idp',                         # 4.2.5.12
        '--dependency-drive-prefix':            '-ddp',                         # 4.2.5.13
        '--drive-prefix':                       '-dp',                          # 4.2.5.14
        '--dependency-target-name':             '-MT',                          # 4.2.5.15
        '--default-stream':                     '-default-stream',              # 4.2.6.1
        '--gpu-architecture':                   '-arch',                        # 4.2.7.1
        '--gpu-code':                           '-code',                        # 4.2.7.2
        '--generate-code':                      '-gencode',                     # 4.2.7.3
        '--relocatable-device-code':            '-rdc',                         # 4.2.7.4
        '--entries':                            '-e',                           # 4.2.7.5
        '--maxrregcount':                       '-maxrregcount',                # 4.2.7.6
        '--ftz':                                '-ftz',                         # 4.2.7.8
        '--prec-div':                           '-prec-div',                    # 4.2.7.9
        '--prec-sqrt':                          '-prec-sqrt',                   # 4.2.7.10
        '--fmad':                               '-fmad',                        # 4.2.7.11
        '--Werror':                             '-Werror',                      # 4.2.8.9
        '--diag-error':                         '-diag-error',                  # 4.2.8.11
        '--diag-suppress':                      '-diag-suppress',               # 4.2.8.12
        '--diag-warn':                          '-diag-warn',                   # 4.2.8.13
        '--options-file':                       '-optf',                        # 4.2.8.17
        '--time':                               '-time',                        # 4.2.8.18
        '--qpp-config':                         '-qpp-config',                  # 4.2.8.19
    }
    # Reverse map -short to --long options.
    _FLAG_SHORT2LONG_WITHARGS = {v: k for k, v in _FLAG_LONG2SHORT_WITHARGS.items()}

    id = 'nvcc'

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice,
                 is_cross: bool,
                 host_compiler: Compiler, info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        super().__init__(ccache, exelist, version, for_machine, info, linker=linker, full_version=full_version, is_cross=is_cross)
        self.host_compiler = host_compiler
        self.base_options = host_compiler.base_options
        # -Wpedantic generates useless churn due to nvcc's dual compilation model producing
        # a temporary host C++ file that includes gcc-style line directives:
        # https://stackoverflow.com/a/31001220
        self.warn_args = {
            level: self._to_host_flags(list(f for f in flags if f != '-Wpedantic'))
            for level, flags in host_compiler.warn_args.items()
        }
        self.host_werror_args = ['-Xcompiler=' + x for x in self.host_compiler.get_werror_args()]

    @classmethod
    def _shield_nvcc_list_arg(cls, arg: str, listmode: bool = True) -> str:
        r"""
        Shield an argument against both splitting by NVCC's list-argument
        parse logic, and interpretation by any shell.

        NVCC seems to consider every comma , that is neither escaped by \ nor inside
        a double-quoted string a split-point. Single-quotes do not provide protection
        against splitting; In fact, after splitting they are \-escaped. Unfortunately,
        double-quotes don't protect against shell expansion. What follows is a
        complex dance to accommodate everybody.
        """

        SQ = "'"
        DQ = '"'
        CM = ","
        BS = "\\"
        DQSQ = DQ+SQ+DQ
        quotable = set(string.whitespace+'"$`\\')

        if CM not in arg or not listmode:
            if SQ not in arg:
                # If any of the special characters "$`\ or whitespace are present, single-quote.
                # Otherwise return bare.
                if set(arg).intersection(quotable):
                    return SQ+arg+SQ
                else:
                    return arg # Easy case: no splits, no quoting.
            else:
                # There are single quotes. Double-quote them, and single-quote the
                # strings between them.
                l = [cls._shield_nvcc_list_arg(s) for s in arg.split(SQ)]
                l = sum([[s, DQSQ] for s in l][:-1], [])  # Interleave l with DQSQs
                return ''.join(l)
        else:
            # A comma is present, and list mode was active.
            # We apply (what we guess is) the (primitive) NVCC splitting rule:
            l = ['']
            instring = False
            argit = iter(arg)
            for c in argit:
                if c == CM and not instring:
                    l.append('')
                elif c == DQ:
                    l[-1] += c
                    instring = not instring
                elif c == BS:
                    try:
                        l[-1] += next(argit)
                    except StopIteration:
                        break
                else:
                    l[-1] += c

            # Shield individual strings, without listmode, then return them with
            # escaped commas between them.
            l = [cls._shield_nvcc_list_arg(s, listmode=False) for s in l]
            return r'\,'.join(l)

    @classmethod
    def _merge_flags(cls, flags: T.List[str]) -> T.List[str]:
        r"""
        The flags to NVCC gets exceedingly verbose and unreadable when too many of them
        are shielded with -Xcompiler. Merge consecutive -Xcompiler-wrapped arguments
        into one.
        """
        if len(flags) <= 1:
            return flags
        flagit = iter(flags)
        xflags = []

        def is_xcompiler_flag_isolated(flag: str) -> bool:
            return flag == '-Xcompiler'

        def is_xcompiler_flag_glued(flag: str) -> bool:
            return flag.startswith('-Xcompiler=')

        def is_xcompiler_flag(flag: str) -> bool:
            return is_xcompiler_flag_isolated(flag) or is_xcompiler_flag_glued(flag)

        def get_xcompiler_val(flag: str, flagit: T.Iterator[str]) -> str:
            if is_xcompiler_flag_glued(flag):
                return flag[len('-Xcompiler='):]
            else:
                try:
                    return next(flagit)
                except StopIteration:
                    return ""

        ingroup = False
        for flag in flagit:
            if not is_xcompiler_flag(flag):
                ingroup = False
                xflags.append(flag)
            elif ingroup:
                xflags[-1] += ','
                xflags[-1] += get_xcompiler_val(flag, flagit)
            elif is_xcompiler_flag_isolated(flag):
                ingroup = True
                xflags.append(flag)
                xflags.append(get_xcompiler_val(flag, flagit))
            elif is_xcompiler_flag_glued(flag):
                ingroup = True
                xflags.append(flag)
            else:
                raise ValueError("-Xcompiler flag merging failed, unknown argument form!")
        return xflags

    def _to_host_flags(self, flags: T.List[str], phase: _Phase = _Phase.COMPILER) -> T.List[str]:
        """
        Translate generic "GCC-speak" plus particular "NVCC-speak" flags to NVCC flags.

        NVCC's "short" flags have broad similarities to the GCC standard, but have
        gratuitous, irritating differences.
        """

        xflags = []
        flagit = iter(flags)

        for flag in flagit:
            # The CUDA Toolkit Documentation, in 4.1. Command Option Types and Notation,
            # specifies that NVCC does not parse the standard flags as GCC does. It has
            # its own strategy, to wit:
            #
            #     nvcc recognizes three types of command options: boolean options, single
            #     value options, and list options.
            #
            #     Boolean options do not have an argument; they are either specified on a
            #     command line or not. Single value options must be specified at most once,
            #     and list options may be repeated. Examples of each of these option types
            #     are, respectively: --verbose (switch to verbose mode), --output-file
            #     (specify output file), and --include-path (specify include path).
            #
            #     Single value options and list options must have arguments, which must
            #     follow the name of the option itself by either one of more spaces or an
            #     equals character. When a one-character short name such as -I, -l, and -L
            #     is used, the value of the option may also immediately follow the option
            #     itself without being separated by spaces or an equal character. The
            #     individual values of list options may be separated by commas in a single
            #     instance of the option, or the option may be repeated, or any
            #     combination of these two cases.
            #
            # One strange consequence of this choice is that directory and filenames that
            # contain commas (',') cannot be passed to NVCC (at least, not as easily as
            # in GCC). Another strange consequence is that it is legal to supply flags
            # such as
            #
            #     -lpthread,rt,dl,util
            #     -l pthread,rt,dl,util
            #     -l=pthread,rt,dl,util
            #
            # and each of the above alternatives is equivalent to GCC-speak
            #
            #     -lpthread -lrt -ldl -lutil
            #     -l pthread -l rt -l dl -l util
            #     -l=pthread -l=rt -l=dl -l=util
            #
            # *With the exception of commas in the name*, GCC-speak for these list flags
            # is a strict subset of NVCC-speak, so we passthrough those flags.
            #
            # The -D macro-define flag is documented as somehow shielding commas from
            # splitting a definition. Balanced parentheses, braces and single-quotes
            # around the comma are not sufficient, but balanced double-quotes are. The
            # shielding appears to work with -l, -I, -L flags as well, for instance.
            #
            # Since our goal is to replicate GCC-speak as much as possible, we check for
            # commas in all list-arguments and shield them with double-quotes. We make
            # an exception for -D (where this would be value-changing) and -U (because
            # it isn't possible to define a macro with a comma in the name).

            if flag in self._FLAG_PASSTHRU_NOARGS:
                xflags.append(flag)
                continue

            # Handle breakup of flag-values into a flag-part and value-part.
            if flag[:1] not in '-/':
                # This is not a flag. It's probably a file input. Pass it through.
                xflags.append(flag)
                continue
            elif flag[:1] == '/':
                # This is ambiguously either an MVSC-style /switch or an absolute path
                # to a file. For some magical reason the following works acceptably in
                # both cases.
                wrap = '"' if ',' in flag else ''
                xflags.append(f'-X{phase.value}={wrap}{flag}{wrap}')
                continue
            elif len(flag) >= 2 and flag[0] == '-' and flag[1] in 'IDULlmOxmte':
                # This is a single-letter short option. These options (with the
                # exception of -o) are allowed to receive their argument with neither
                # space nor = sign before them. Detect and separate them in that event.
                if flag[2:3] == '':            # -I something
                    try:
                        val = next(flagit)
                    except StopIteration:
                        pass
                elif flag[2:3] == '=':           # -I=something
                    val = flag[3:]
                else:                            # -Isomething
                    val = flag[2:]
                flag = flag[:2]                  # -I
            elif flag in self._FLAG_LONG2SHORT_WITHARGS or \
                    flag in self._FLAG_SHORT2LONG_WITHARGS:
                # This is either -o or a multi-letter flag, and it is receiving its
                # value isolated.
                try:
                    val = next(flagit)           # -o something
                except StopIteration:
                    pass
            elif flag.split('=', 1)[0] in self._FLAG_LONG2SHORT_WITHARGS or \
                    flag.split('=', 1)[0] in self._FLAG_SHORT2LONG_WITHARGS:
                # This is either -o or a multi-letter flag, and it is receiving its
                # value after an = sign.
                flag, val = flag.split('=', 1)    # -o=something
            # Some dependencies (e.g., BoostDependency) add unspaced "-isystem/usr/include" arguments
            elif flag.startswith('-isystem'):
                val = flag[8:].strip()
                flag = flag[:8]
            else:
                # This is a flag, and it's foreign to NVCC.
                #
                # We do not know whether this GCC-speak flag takes an isolated
                # argument. Assuming it does not (the vast majority indeed don't),
                # wrap this argument in an -Xcompiler flag and send it down to NVCC.
                if flag == '-ffast-math':
                    xflags.append('-use_fast_math')
                    xflags.append('-Xcompiler='+flag)
                elif flag == '-fno-fast-math':
                    xflags.append('-ftz=false')
                    xflags.append('-prec-div=true')
                    xflags.append('-prec-sqrt=true')
                    xflags.append('-Xcompiler='+flag)
                elif flag == '-freciprocal-math':
                    xflags.append('-prec-div=false')
                    xflags.append('-Xcompiler='+flag)
                elif flag == '-fno-reciprocal-math':
                    xflags.append('-prec-div=true')
                    xflags.append('-Xcompiler='+flag)
                else:
                    xflags.append('-Xcompiler='+self._shield_nvcc_list_arg(flag))
                    # The above should securely handle GCC's -Wl, -Wa, -Wp, arguments.
                continue

            assert val is not None  # Should only trip if there is a missing argument.

            # Take care of the various NVCC-supported flags that need special handling.
            flag = self._FLAG_LONG2SHORT_WITHARGS.get(flag, flag)

            if flag in {'-include', '-isystem', '-I', '-L', '-l'}:
                # These flags are known to GCC, but list-valued in NVCC. They potentially
                # require double-quoting to prevent NVCC interpreting the flags as lists
                # when GCC would not have done so.
                #
                # We avoid doing this quoting for -D to avoid redefining macros and for
                # -U because it isn't possible to define a macro with a comma in the name.
                # -U with comma arguments is impossible in GCC-speak (and thus unambiguous
                #in NVCC-speak, albeit unportable).
                if len(flag) == 2:
                    xflags.append(flag+self._shield_nvcc_list_arg(val))
                elif flag == '-isystem' and val in self.host_compiler.get_default_include_dirs():
                    # like GnuLikeCompiler, we have to filter out include directories specified
                    # with -isystem that overlap with the host compiler's search path
                    pass
                else:
                    xflags.append(flag)
                    xflags.append(self._shield_nvcc_list_arg(val))
            elif flag == '-O':
                # Handle optimization levels GCC knows about that NVCC does not.
                if val == 'fast':
                    xflags.append('-O3')
                    xflags.append('-use_fast_math')
                    xflags.append('-Xcompiler')
                    xflags.append(flag+val)
                elif val in {'s', 'g', 'z'}:
                    xflags.append('-Xcompiler')
                    xflags.append(flag+val)
                else:
                    xflags.append(flag+val)
            elif flag in {'-D', '-U', '-m', '-t'}:
                xflags.append(flag+val)       # For style, keep glued.
            elif flag in {'-std'}:
                xflags.append(flag+'='+val)   # For style, keep glued.
            else:
                xflags.append(flag)
                xflags.append(val)

        return self._merge_flags(xflags)

    def needs_static_linker(self) -> bool:
        return False

    def thread_link_flags(self, environment: 'Environment') -> T.List[str]:
        return self._to_host_flags(self.host_compiler.thread_link_flags(environment), _Phase.LINKER)

    def sanity_check(self, work_dir: str, env: 'Environment') -> None:
        mlog.debug('Sanity testing ' + self.get_display_language() + ' compiler:', ' '.join(self.exelist))
        mlog.debug('Is cross compiler: %s.' % str(self.is_cross))

        sname = 'sanitycheckcuda.cu'
        code = r'''
        #include <cuda_runtime.h>
        #include <stdio.h>

        __global__ void kernel (void) {}

        int main(void){
            struct cudaDeviceProp prop;
            int count, i;
            cudaError_t ret = cudaGetDeviceCount(&count);
            if(ret != cudaSuccess){
                fprintf(stderr, "%d\n", (int)ret);
            }else{
                for(i=0;i<count;i++){
                    if(cudaGetDeviceProperties(&prop, i) == cudaSuccess){
                        fprintf(stdout, "%d.%d\n", prop.major, prop.minor);
                    }
                }
            }
            fflush(stderr);
            fflush(stdout);
            return 0;
        }
        '''
        binname = sname.rsplit('.', 1)[0]
        binname += '_cross' if self.is_cross else ''
        source_name = os.path.join(work_dir, sname)
        binary_name = os.path.join(work_dir, binname + '.exe')
        with open(source_name, 'w', encoding='utf-8') as ofile:
            ofile.write(code)

        # The Sanity Test for CUDA language will serve as both a sanity test
        # and a native-build GPU architecture detection test, useful later.
        #
        # For this second purpose, NVCC has very handy flags, --run and
        # --run-args, that allow one to run an application with the
        # environment set up properly. Of course, this only works for native
        # builds; For cross builds we must still use the exe_wrapper (if any).
        self.detected_cc = ''
        flags = []

        # Disable warnings, compile with statically-linked runtime for minimum
        # reliance on the system.
        flags += ['-w', '-cudart', 'static', source_name]

        # Use the -ccbin option, if available, even during sanity checking.
        # Otherwise, on systems where CUDA does not support the default compiler,
        # NVCC becomes unusable.
        flags += self.get_ccbin_args(env.coredata.options)

        # If cross-compiling, we can't run the sanity check, only compile it.
        if env.need_exe_wrapper(self.for_machine) and not env.has_exe_wrapper():
            # Linking cross built apps is painful. You can't really
            # tell if you should use -nostdlib or not and for example
            # on OSX the compiler binary is the same but you need
            # a ton of compiler flags to differentiate between
            # arm and x86_64. So just compile.
            flags += self.get_compile_only_args()
        flags += self.get_output_args(binary_name)

        # Compile sanity check
        cmdlist = self.exelist + flags
        mlog.debug('Sanity check compiler command line: ', ' '.join(cmdlist))
        pc, stdo, stde = Popen_safe(cmdlist, cwd=work_dir)
        mlog.debug('Sanity check compile stdout: ')
        mlog.debug(stdo)
        mlog.debug('-----\nSanity check compile stderr:')
        mlog.debug(stde)
        mlog.debug('-----')
        if pc.returncode != 0:
            raise EnvironmentException(f'Compiler {self.name_string()} cannot compile programs.')

        # Run sanity check (if possible)
        if env.need_exe_wrapper(self.for_machine):
            if not env.has_exe_wrapper():
                return
            else:
                cmdlist = env.exe_wrapper.get_command() + [binary_name]
        else:
            cmdlist = self.exelist + ['--run', '"' + binary_name + '"']
        mlog.debug('Sanity check run command line: ', ' '.join(cmdlist))
        pe, stdo, stde = Popen_safe(cmdlist, cwd=work_dir)
        mlog.debug('Sanity check run stdout: ')
        mlog.debug(stdo)
        mlog.debug('-----\nSanity check run stderr:')
        mlog.debug(stde)
        mlog.debug('-----')
        pe.wait()
        if pe.returncode != 0:
            raise EnvironmentException(f'Executables created by {self.language} compiler {self.name_string()} are not runnable.')

        # Interpret the result of the sanity test.
        # As mentioned above, it is not only a sanity test but also a GPU
        # architecture detection test.
        if stde == '':
            self.detected_cc = stdo
        else:
            mlog.debug('cudaGetDeviceCount() returned ' + stde)

    def has_header_symbol(self, hname: str, symbol: str, prefix: str,
                          env: 'Environment', *,
                          extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
                          dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        if extra_args is None:
            extra_args = []
        fargs = {'prefix': prefix, 'header': hname, 'symbol': symbol}
        # Check if it's a C-like symbol
        t = '''{prefix}
        #include <{header}>
        int main(void) {{
            /* If it's not defined as a macro, try to use as a symbol */
            #ifndef {symbol}
                {symbol};
            #endif
            return 0;
        }}'''
        found, cached = self.compiles(t.format_map(fargs), env, extra_args=extra_args, dependencies=dependencies)
        if found:
            return True, cached
        # Check if it's a class or a template
        t = '''{prefix}
        #include <{header}>
        using {symbol};
        int main(vo
"""


```