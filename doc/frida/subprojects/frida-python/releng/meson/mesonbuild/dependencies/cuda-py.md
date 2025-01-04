Response:
Let's break down the thought process for analyzing this Python code.

**1. Understanding the Goal:**

The request asks for an explanation of the `cuda.py` file's functionality within the context of Frida, focusing on its relation to reverse engineering, low-level details, logic, potential errors, and user interaction.

**2. Initial Code Scan & Keyword Identification:**

I'd start by quickly scanning the code for key terms and patterns that suggest its purpose. Keywords like "CUDA," "dependency," "compiler," "linker," "path," "version," "library," "modules," and methods like `find_library`, `get_link_args`, `_detect_cuda_path_and_version` immediately stand out. This suggests it's about finding and linking against the CUDA library.

**3. Deeper Dive into Core Functionality:**

Next, I'd examine the main class, `CudaDependency`, and its methods.

* **`__init__`:** This is the entry point. It initializes the dependency, detects the language (CUDA, C++, or C), handles requested modules (like `cudart`), and importantly, calls `_detect_cuda_path_and_version`. The logic around defaulting to static linking (`cudart_static`) is also interesting.
* **`_detect_cuda_path_and_version`:**  This is crucial. It's responsible for finding the CUDA installation. I'd pay attention to how it looks for paths (environment variables, default locations like `/usr/local/cuda`), checks versions (using `version.txt` and `cuda_runtime_api.h`), and compares against requested versions.
* **`_find_requested_libraries`:** This confirms the presence of the specified CUDA modules (like `cudart`).
* **`get_link_args`:**  This method generates the necessary linker flags to use the CUDA library.
* **`_detect_arch_libdir`:** This determines the correct architecture-specific library directory (e.g., `lib64`, `x64`).

**4. Connecting to Reverse Engineering:**

At this point, I'd start connecting the dots to reverse engineering. Frida is a dynamic instrumentation tool, and CUDA is often used in performance-critical applications, including those that might be targets for reverse engineering. The ability to hook or modify CUDA functions within a running process is a powerful reverse engineering technique. This dependency allows Frida to build components that interact with CUDA-enabled applications.

**5. Identifying Low-Level Aspects:**

The code clearly deals with low-level concepts:

* **Binary Linking:** The `get_link_args` method is directly involved in the binary linking process.
* **Operating System Differences:** The code explicitly handles Windows, Linux, and macOS (`_is_windows`, `_cuda_paths_win`, `_cuda_paths_nix`).
* **Architecture Specifics:**  `_detect_arch_libdir` highlights the need to select the correct library based on the target architecture.
* **Environment Variables:** Reliance on environment variables like `CUDA_PATH`.

**6. Analyzing Logic and Assumptions:**

I'd look for decision points and assumptions made by the code:

* **Version Matching:** The logic in `_find_matching_toolkit` demonstrates a clear strategy for selecting the correct CUDA version. The handling of default paths and potential mismatches with `nvcc` version is important.
* **Default Modules:** The code assumes `cudart` or `cudart_static` is often needed.
* **Path Conventions:** The hardcoded paths like `/usr/local/cuda` are assumptions about common CUDA installations.

**7. Spotting Potential Errors and User Mistakes:**

Considering how a user might interact with this, I'd think about potential problems:

* **Incorrect CUDA Path:** The most obvious error is an incorrect `CUDA_PATH`.
* **Missing Modules:** Requesting a module that doesn't exist.
* **Version Mismatches:**  Specifying a version that isn't installed.
* **Architecture Issues:** Trying to build for the wrong architecture.

**8. Tracing User Interaction (Debugging Clues):**

To understand how a user reaches this code, I'd consider the build process:

1. **Frida Build System:** Frida uses Meson as its build system.
2. **Dependency Declaration:**  A `meson.build` file would likely declare a dependency on `cuda`.
3. **Meson's Dependency Resolution:** Meson would then invoke the `CudaDependency` class to find and configure the CUDA library.
4. **User Configuration:** The user might influence this by setting environment variables or passing arguments to the `dependency()` function in `meson.build`.

**9. Structuring the Answer:**

Finally, I'd organize the findings into the requested categories: functionality, reverse engineering relevance, low-level details, logic, errors, and user interaction. Using examples is crucial for clarity. I'd also try to use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just about finding CUDA."  **Correction:**  It's more about integrating CUDA into the build process *for Frida*, which has implications for reverse engineering.
* **Overlooking details:** I might initially miss the nuances of static vs. dynamic linking or the subtle differences between Windows and Linux path handling. A closer reading is needed.
* **Lack of examples:**  Simply stating facts isn't enough. I need concrete examples to illustrate the points. For example, instead of saying "it checks versions," I'd show an example of a version string or a `version` argument in the `dependency()` call.

By following this systematic approach, combining code analysis with an understanding of the surrounding context (Frida, build systems, CUDA's role), I can generate a comprehensive and accurate explanation.
这个Python文件 `cuda.py` 是 Frida 动态 instrumentation 工具中用于检测和配置 CUDA 依赖项的模块。 它的主要功能是帮助 Meson 构建系统找到系统中安装的 CUDA 工具包，并提供编译和链接 CUDA 代码所需的必要信息。

以下是该文件的详细功能列表，以及与逆向、底层、内核、用户错误和调试的关联说明：

**主要功能:**

1. **检测 CUDA 工具包路径和版本:**
   - 它会搜索系统中的 CUDA 工具包安装路径，优先考虑环境变量 (`CUDA_PATH`, `CUDA_HOME`, `CUDA_ROOT`) 和默认路径 (`/usr/local/cuda` 在 Linux 上)。
   - 它会读取 CUDA 工具包的 `version.txt` 文件或者 `cuda_runtime_api.h` 头文件来获取 CUDA 版本信息。
   - 它会根据用户指定的版本要求（通过 `dependency('cuda', version: '>=11.0')`）来匹配合适的 CUDA 工具包。

2. **确定 CUDA 库的链接参数:**
   - 它会根据目标平台（Windows, Linux, macOS）和 CPU 架构（x86, x86_64, arm64 等）确定 CUDA 库所在的目录（例如 `lib64`, `x64`）。
   - 它会查找用户请求的 CUDA 模块（例如 `cudart`, `nvrtc`, `cublas`）。
   - 它会生成链接器参数，以便将这些 CUDA 库链接到最终的可执行文件或共享库中。

3. **提供 CUDA 编译器的包含路径:**
   - 它会设置 CUDA 头文件的包含路径，以便在编译 CUDA 代码时能够找到必要的头文件。

4. **处理 CUDA 语言支持:**
   - 它支持 CUDA、C++ 和 C 语言的 CUDA 代码编译。
   - 如果项目同时包含 CUDA 和其他语言的代码，它会确保编译器能够正确地找到 CUDA 的头文件和库。

5. **管理 CUDA 模块依赖:**
   - 用户可以在 Meson 的 `dependency()` 函数中指定需要的 CUDA 模块。
   - 默认情况下，它会尝试链接 CUDA 运行时库 (`cudart` 或 `cudart_static`)。

**与逆向方法的关联 (举例说明):**

* **动态分析 CUDA 应用:** Frida 可以被用来 hook 运行中的 CUDA 应用程序的 API 调用。为了实现这一点，Frida 需要能够找到目标系统上的 CUDA 库。`cuda.py` 模块确保 Frida 的构建系统能够正确地链接到 CUDA 库，这样 Frida 才能在运行时与 CUDA 代码交互。
    * **假设输入:** 用户使用 Frida attach 到一个正在运行的使用 CUDA 的程序。
    * **输出:** Frida 能够加载并与目标进程中的 CUDA 库交互，例如 hook `cudaMalloc` 或其他 CUDA API 调用来监控内存分配或参数。

* **分析 CUDA 驱动或运行时库:** 逆向工程师可能需要分析底层的 CUDA 驱动或运行时库的行为。`cuda.py` 模块可以帮助构建用于分析这些库的工具，因为它提供了找到这些库的路径和链接它们的方法。
    * **假设输入:** 开发者想要构建一个工具来分析 CUDA 运行时库的内部工作原理。
    * **输出:** 使用 `cuda.py` 提供的信息，构建系统可以正确链接到 CUDA 运行时库，开发者可以使用反汇编器或调试器来分析其代码。

**涉及二进制底层、Linux、Android 内核及框架的知识 (举例说明):**

* **二进制链接:**  `get_link_args` 方法直接操作二进制链接的过程，生成 `-L` (指定库路径) 和 `-l` (指定要链接的库) 等链接器参数。这是二进制文件构建的底层操作。
    * **例子:** 在 Linux 上，`self.clib_compiler.find_library('cudart', self.env, [self.libdir])` 会尝试在 `self.libdir` 中找到 `libcudart.so`。

* **Linux 库路径约定:** 代码中使用了 `/usr/local/cuda` 作为默认的 CUDA 安装路径，这是 Linux 上的常见约定。它还考虑了环境变量，这是 Linux 系统中配置库路径的常用方法。
    * **例子:** `pattern = '/usr/local/cuda-*' if self.env_var else '/usr/local/cuda*'` 这行代码展示了在 Linux 上搜索 CUDA 安装路径的模式。

* **CPU 架构相关的库目录:** `_detect_arch_libdir` 方法根据不同的 CPU 架构（x86_64, aarch64 等）选择不同的库目录 (`lib64`, `lib`)。这是因为不同的架构使用不同的指令集和 ABI (Application Binary Interface)，需要不同的库文件。
    * **例子:** 在 Linux x86_64 系统上，CUDA 库通常位于 `/usr/local/cuda/lib64`。

* **操作系统特定的路径和环境变量:** 代码区分了 Windows (`CUDA_PATH_*`) 和类 Unix 系统 (`CUDA_PATH`, `CUDA_HOME`, `CUDA_ROOT`) 上查找 CUDA 路径的方式。这反映了不同操作系统在环境变量和目录结构上的差异。

**逻辑推理 (假设输入与输出):**

* **假设输入:** 用户在 `meson.build` 文件中指定了 `dependency('cuda', version: '>=10.2', modules: ['cudart', 'nvrtc'])`，并且系统上安装了 CUDA 11.5 和 CUDA 10.1。环境变量 `CUDA_PATH` 指向 CUDA 11.5 的安装路径。
* **输出:**
    - `_detect_cuda_path_and_version` 方法会优先检测到 `CUDA_PATH` 指向的 CUDA 11.5，并将其版本解析为 "11.5"。因为 11.5 满足 `>=10.2` 的要求，所以 `self.cuda_path` 将被设置为 CUDA 11.5 的安装路径，`self.version` 将为 "11.5"。
    - `_find_requested_libraries` 方法会在 CUDA 11.5 的库目录中查找 `cudart` 和 `nvrtc` 库，并将它们的链接参数存储在 `self.lib_modules` 中。

**涉及用户或编程常见的使用错误 (举例说明):**

* **CUDA_PATH 未设置或设置错误:** 如果用户没有设置 `CUDA_PATH` 环境变量，或者设置的路径不正确，`_detect_cuda_path_and_version` 方法可能无法找到 CUDA 工具包，导致构建失败。
    * **错误信息:**  可能会抛出 `DependencyException`，提示用户设置 `CUDA_PATH` 环境变量。

* **请求不存在的 CUDA 模块:** 用户可能在 `modules` 参数中请求了一个不存在的 CUDA 模块，例如 `dependency('cuda', modules: ['nonexistent_module'])`.
    * **错误信息:** `_find_requested_libraries` 方法会报错，提示找不到请求的 CUDA 模块。

* **指定的 CUDA 版本与系统安装的版本不匹配:** 用户可能指定了特定的 CUDA 版本要求，但系统上安装的 CUDA 版本不满足要求。
    * **错误信息:** `_detect_cuda_path_and_version` 方法会比较版本，如果找不到匹配的版本，会抛出 `DependencyException`。

* **静态链接 CUDA 运行时库时缺少依赖:** 在 Linux 上静态链接 `cudart_static` 时，代码会添加 `rt`, `pthread`, `dl` 等依赖。如果这些依赖在系统上缺失，链接过程可能会失败。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试构建一个依赖 CUDA 的 Frida 组件或模块:** 用户通常会执行类似 `meson build` 或 `ninja` 的构建命令。
2. **Meson 解析 `meson.build` 文件:** Meson 会读取项目根目录下的 `meson.build` 文件，其中包含了项目的构建配置信息，包括依赖项声明。
3. **遇到 CUDA 依赖声明:**  当 Meson 解析到类似 `cuda_dep = dependency('cuda', version: '>=11.0')` 的语句时，它会尝试解析这个 CUDA 依赖。
4. **Meson 调用 `CudaDependency` 类:**  Meson 的依赖管理系统会找到并实例化与 `'cuda'` 关联的 `CudaDependency` 类（通过 `packages['cuda'] = CudaDependency` 注册）。
5. **执行 `CudaDependency` 的 `__init__` 方法:**  `__init__` 方法会开始执行上述的各种检测和配置操作，例如查找 CUDA 路径、版本和库。
6. **如果在检测过程中发生错误:** 例如，找不到 CUDA 工具包或请求的模块，`_report_dependency_error` 方法会被调用，可能会抛出异常并终止构建过程，同时输出相关的错误信息。
7. **调试线索:** 如果用户遇到与 CUDA 相关的构建错误，他们应该检查以下内容：
    - 环境变量 `CUDA_PATH` 是否正确设置。
    - 系统上是否安装了满足版本要求的 CUDA 工具包。
    - 请求的 CUDA 模块名称是否正确。
    - 操作系统和 CPU 架构是否与 CUDA 工具包兼容。
    - Meson 的配置是否正确。

通过理解 `cuda.py` 文件的功能和它在构建过程中的作用，用户可以更好地诊断和解决与 CUDA 依赖相关的构建问题。 该文件是 Frida 构建系统中处理 CUDA 集成的一个关键组件。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/dependencies/cuda.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2013-2019 The Meson development team

from __future__ import annotations

import glob
import re
import os
import typing as T
from pathlib import Path

from .. import mesonlib
from .. import mlog
from ..environment import detect_cpu_family
from .base import DependencyException, SystemDependency
from .detect import packages


if T.TYPE_CHECKING:
    from ..environment import Environment
    from ..compilers import Compiler

    TV_ResultTuple = T.Tuple[T.Optional[str], T.Optional[str], bool]

class CudaDependency(SystemDependency):

    supported_languages = ['cuda', 'cpp', 'c'] # see also _default_language

    def __init__(self, environment: 'Environment', kwargs: T.Dict[str, T.Any]) -> None:
        compilers = environment.coredata.compilers[self.get_for_machine_from_kwargs(kwargs)]
        language = self._detect_language(compilers)
        if language not in self.supported_languages:
            raise DependencyException(f'Language \'{language}\' is not supported by the CUDA Toolkit. Supported languages are {self.supported_languages}.')

        super().__init__('cuda', environment, kwargs, language=language)
        self.lib_modules: T.Dict[str, T.List[str]] = {}
        self.requested_modules = self.get_requested(kwargs)
        if not any(runtime in self.requested_modules for runtime in ['cudart', 'cudart_static']):
            # By default, we prefer to link the static CUDA runtime, since this is what nvcc also does by default:
            # https://docs.nvidia.com/cuda/cuda-compiler-driver-nvcc/index.html#cudart-none-shared-static-cudart
            req_modules = ['cudart']
            if kwargs.get('static', True):
                req_modules = ['cudart_static']
                machine = self.env.machines[self.for_machine]
                if machine.is_linux():
                    # extracted by running
                    #   nvcc -v foo.o
                    req_modules += ['rt', 'pthread', 'dl']
            self.requested_modules = req_modules + self.requested_modules

        (self.cuda_path, self.version, self.is_found) = self._detect_cuda_path_and_version()
        if not self.is_found:
            return

        if not os.path.isabs(self.cuda_path):
            raise DependencyException(f'CUDA Toolkit path must be absolute, got \'{self.cuda_path}\'.')

        # nvcc already knows where to find the CUDA Toolkit, but if we're compiling
        # a mixed C/C++/CUDA project, we still need to make the include dir searchable
        if self.language != 'cuda' or len(compilers) > 1:
            self.incdir = os.path.join(self.cuda_path, 'include')
            self.compile_args += [f'-I{self.incdir}']

        if self.language != 'cuda':
            arch_libdir = self._detect_arch_libdir()
            self.libdir = os.path.join(self.cuda_path, arch_libdir)
            mlog.debug('CUDA library directory is', mlog.bold(self.libdir))
        else:
            self.libdir = None

        self.is_found = self._find_requested_libraries()

    @classmethod
    def _detect_language(cls, compilers: T.Dict[str, 'Compiler']) -> str:
        for lang in cls.supported_languages:
            if lang in compilers:
                return lang
        return list(compilers.keys())[0]

    def _detect_cuda_path_and_version(self) -> TV_ResultTuple:
        self.env_var = self._default_path_env_var()
        mlog.debug('Default path env var:', mlog.bold(self.env_var))

        version_reqs = self.version_reqs
        if self.language == 'cuda':
            nvcc_version = self._strip_patch_version(self.get_compiler().version)
            mlog.debug('nvcc version:', mlog.bold(nvcc_version))
            if version_reqs:
                # make sure nvcc version satisfies specified version requirements
                (found_some, not_found, found) = mesonlib.version_compare_many(nvcc_version, version_reqs)
                if not_found:
                    msg = f'The current nvcc version {nvcc_version} does not satisfy the specified CUDA Toolkit version requirements {version_reqs}.'
                    return self._report_dependency_error(msg, (None, None, False))

            # use nvcc version to find a matching CUDA Toolkit
            version_reqs = [f'={nvcc_version}']
        else:
            nvcc_version = None

        paths = [(path, self._cuda_toolkit_version(path), default) for (path, default) in self._cuda_paths()]
        if version_reqs:
            return self._find_matching_toolkit(paths, version_reqs, nvcc_version)

        defaults = [(path, version) for (path, version, default) in paths if default]
        if defaults:
            return (defaults[0][0], defaults[0][1], True)

        platform_msg = 'set the CUDA_PATH environment variable' if self._is_windows() \
            else 'set the CUDA_PATH environment variable/create the \'/usr/local/cuda\' symbolic link'
        msg = f'Please specify the desired CUDA Toolkit version (e.g. dependency(\'cuda\', version : \'>=10.1\')) or {platform_msg} to point to the location of your desired version.'
        return self._report_dependency_error(msg, (None, None, False))

    def _find_matching_toolkit(self, paths: T.List[TV_ResultTuple], version_reqs: T.List[str], nvcc_version: T.Optional[str]) -> TV_ResultTuple:
        # keep the default paths order intact, sort the rest in the descending order
        # according to the toolkit version
        part_func: T.Callable[[TV_ResultTuple], bool] = lambda t: not t[2]
        defaults_it, rest_it = mesonlib.partition(part_func, paths)
        defaults = list(defaults_it)
        paths = defaults + sorted(rest_it, key=lambda t: mesonlib.Version(t[1]), reverse=True)
        mlog.debug(f'Search paths: {paths}')

        if nvcc_version and defaults:
            default_src = f"the {self.env_var} environment variable" if self.env_var else "the \'/usr/local/cuda\' symbolic link"
            nvcc_warning = 'The default CUDA Toolkit as designated by {} ({}) doesn\'t match the current nvcc version {} and will be ignored.'.format(default_src, os.path.realpath(defaults[0][0]), nvcc_version)
        else:
            nvcc_warning = None

        for (path, version, default) in paths:
            (found_some, not_found, found) = mesonlib.version_compare_many(version, version_reqs)
            if not not_found:
                if not default and nvcc_warning:
                    mlog.warning(nvcc_warning)
                return (path, version, True)

        if nvcc_warning:
            mlog.warning(nvcc_warning)
        return (None, None, False)

    def _default_path_env_var(self) -> T.Optional[str]:
        env_vars = ['CUDA_PATH'] if self._is_windows() else ['CUDA_PATH', 'CUDA_HOME', 'CUDA_ROOT']
        env_vars = [var for var in env_vars if var in os.environ]
        user_defaults = {os.environ[var] for var in env_vars}
        if len(user_defaults) > 1:
            mlog.warning('Environment variables {} point to conflicting toolkit locations ({}). Toolkit selection might produce unexpected results.'.format(', '.join(env_vars), ', '.join(user_defaults)))
        return env_vars[0] if env_vars else None

    def _cuda_paths(self) -> T.List[T.Tuple[str, bool]]:
        return ([(os.environ[self.env_var], True)] if self.env_var else []) \
            + (self._cuda_paths_win() if self._is_windows() else self._cuda_paths_nix())

    def _cuda_paths_win(self) -> T.List[T.Tuple[str, bool]]:
        env_vars = os.environ.keys()
        return [(os.environ[var], False) for var in env_vars if var.startswith('CUDA_PATH_')]

    def _cuda_paths_nix(self) -> T.List[T.Tuple[str, bool]]:
        # include /usr/local/cuda default only if no env_var was found
        pattern = '/usr/local/cuda-*' if self.env_var else '/usr/local/cuda*'
        return [(path, os.path.basename(path) == 'cuda') for path in glob.iglob(pattern)]

    toolkit_version_regex = re.compile(r'^CUDA Version\s+(.*)$')
    path_version_win_regex = re.compile(r'^v(.*)$')
    path_version_nix_regex = re.compile(r'^cuda-(.*)$')
    cudart_version_regex = re.compile(r'#define\s+CUDART_VERSION\s+([0-9]+)')

    def _cuda_toolkit_version(self, path: str) -> str:
        version = self._read_toolkit_version_txt(path)
        if version:
            return version
        version = self._read_cuda_runtime_api_version(path)
        if version:
            return version

        mlog.debug('Falling back to extracting version from path')
        path_version_regex = self.path_version_win_regex if self._is_windows() else self.path_version_nix_regex
        try:
            m = path_version_regex.match(os.path.basename(path))
            if m:
                return m.group(1)
            else:
                mlog.warning(f'Could not detect CUDA Toolkit version for {path}')
        except Exception as e:
            mlog.warning(f'Could not detect CUDA Toolkit version for {path}: {e!s}')

        return '0.0'

    def _read_cuda_runtime_api_version(self, path_str: str) -> T.Optional[str]:
        path = Path(path_str)
        for i in path.rglob('cuda_runtime_api.h'):
            raw = i.read_text(encoding='utf-8')
            m = self.cudart_version_regex.search(raw)
            if not m:
                continue
            try:
                vers_int = int(m.group(1))
            except ValueError:
                continue
            # use // for floor instead of / which produces a float
            major = vers_int // 1000
            minor = (vers_int - major * 1000) // 10
            return f'{major}.{minor}'
        return None

    def _read_toolkit_version_txt(self, path: str) -> T.Optional[str]:
        # Read 'version.txt' at the root of the CUDA Toolkit directory to determine the toolkit version
        version_file_path = os.path.join(path, 'version.txt')
        try:
            with open(version_file_path, encoding='utf-8') as version_file:
                version_str = version_file.readline() # e.g. 'CUDA Version 10.1.168'
                m = self.toolkit_version_regex.match(version_str)
                if m:
                    return self._strip_patch_version(m.group(1))
        except Exception as e:
            mlog.debug(f'Could not read CUDA Toolkit\'s version file {version_file_path}: {e!s}')

        return None

    @classmethod
    def _strip_patch_version(cls, version: str) -> str:
        return '.'.join(version.split('.')[:2])

    def _detect_arch_libdir(self) -> str:
        arch = detect_cpu_family(self.env.coredata.compilers.host)
        machine = self.env.machines[self.for_machine]
        msg = '{} architecture is not supported in {} version of the CUDA Toolkit.'
        if machine.is_windows():
            libdirs = {'x86': 'Win32', 'x86_64': 'x64'}
            if arch not in libdirs:
                raise DependencyException(msg.format(arch, 'Windows'))
            return os.path.join('lib', libdirs[arch])
        elif machine.is_linux():
            libdirs = {'x86_64': 'lib64', 'ppc64': 'lib', 'aarch64': 'lib64', 'loongarch64': 'lib64'}
            if arch not in libdirs:
                raise DependencyException(msg.format(arch, 'Linux'))
            return libdirs[arch]
        elif machine.is_darwin():
            libdirs = {'x86_64': 'lib64'}
            if arch not in libdirs:
                raise DependencyException(msg.format(arch, 'macOS'))
            return libdirs[arch]
        else:
            raise DependencyException('CUDA Toolkit: unsupported platform.')

    def _find_requested_libraries(self) -> bool:
        all_found = True

        for module in self.requested_modules:
            args = self.clib_compiler.find_library(module, self.env, [self.libdir] if self.libdir else [])
            if args is None:
                self._report_dependency_error(f'Couldn\'t find requested CUDA module \'{module}\'')
                all_found = False
            else:
                mlog.debug(f'Link args for CUDA module \'{module}\' are {args}')
                self.lib_modules[module] = args

        return all_found

    def _is_windows(self) -> bool:
        return self.env.machines[self.for_machine].is_windows()

    @T.overload
    def _report_dependency_error(self, msg: str) -> None: ...

    @T.overload
    def _report_dependency_error(self, msg: str, ret_val: TV_ResultTuple) -> TV_ResultTuple: ... # noqa: F811

    def _report_dependency_error(self, msg: str, ret_val: T.Optional[TV_ResultTuple] = None) -> T.Optional[TV_ResultTuple]: # noqa: F811
        if self.required:
            raise DependencyException(msg)

        mlog.debug(msg)
        return ret_val

    def log_details(self) -> str:
        module_str = ', '.join(self.requested_modules)
        return 'modules: ' + module_str

    def log_info(self) -> str:
        return self.cuda_path if self.cuda_path else ''

    def get_requested(self, kwargs: T.Dict[str, T.Any]) -> T.List[str]:
        candidates = mesonlib.extract_as_list(kwargs, 'modules')
        for c in candidates:
            if not isinstance(c, str):
                raise DependencyException('CUDA module argument is not a string.')
        return candidates

    def get_link_args(self, language: T.Optional[str] = None, raw: bool = False) -> T.List[str]:
        args: T.List[str] = []
        if self.libdir:
            args += self.clib_compiler.get_linker_search_args(self.libdir)
        for lib in self.requested_modules:
            args += self.lib_modules[lib]
        return args

packages['cuda'] = CudaDependency

"""

```