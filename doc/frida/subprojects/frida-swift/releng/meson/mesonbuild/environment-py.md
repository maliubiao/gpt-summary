Response:
The user wants a summary of the functionality of the provided Python code. I need to go through the code and identify the key purposes of the functions and classes defined. I should also address the specific points raised in the prompt: relationship with reverse engineering, involvement of low-level/kernel/framework knowledge, logical reasoning, potential user errors, and how a user might reach this code.

**Plan:**
1. Read through the code and identify the primary functions and classes.
2. Summarize the core functionality related to environment setup and detection.
3. Address the relationship with reverse engineering – this file seems focused on build environment setup, so the direct link might be weak, but consider indirect connections.
4. Identify areas involving low-level details, particularly in the `detect_*` functions related to OS, CPU architecture, and tools.
5. Look for logical reasoning and provide input/output examples where applicable.
6. Analyze potential user errors related to environment variable settings and configuration files.
7. Describe the user actions that would lead to the execution of this code as part of the Meson build process.
8. Finally, synthesize a concise summary of the file's functions.
好的，根据您提供的 frida/subprojects/frida-swift/releng/meson/mesonbuild/environment.py 文件的代码，这个文件的主要功能是：

**核心功能：构建环境的检测与配置**

该文件的核心职责是检测和配置 Meson 构建系统所需的各种环境信息，包括：

1. **操作系统和硬件信息检测:**
    *   检测当前的操作系统 (Windows, Linux, macOS, etc.) 和内核类型。
    *   检测 CPU 架构 (x86, x86\_64, ARM, AArch64, etc.) 和 CPU 系列。
    *   尝试通过编译器内置宏来更精确地判断 CPU 架构。

2. **构建工具检测:**
    *   检测如 `ninja`, `cmake`, `pkg-config` 等构建工具是否存在以及版本是否满足要求。
    *   特别地，它会检测代码覆盖率工具，如 `gcovr`, `lcov`, `llvm-cov` 及其相关工具 `genhtml`。
    *   还会检测静态代码分析工具，如 `scan-build` 和代码格式化工具 `clang-format`。

3. **环境变量处理:**
    *   读取并处理与构建相关的环境变量，例如 `CFLAGS`, `LDFLAGS`, `PKG_CONFIG_PATH`, `CMAKE_PREFIX_PATH` 等。
    *   区分针对 build 机器和 host 机器的环境变量 (例如 `VAR_NAME_FOR_BUILD` 和 `VAR_NAME`)。

4. **配置文件处理:**
    *   读取并解析 `meson.build` 文件以及 native 和 cross-compilation 配置文件。
    *   处理配置文件中的选项 (options)、二进制工具路径 (binaries) 和属性 (properties)。

5. **初始化构建环境对象 (Environment class):**
    *   创建 `Environment` 类的实例，该实例存储了检测到的所有环境信息，包括编译器信息、构建工具路径、选项设置等。
    *   负责加载或创建 `coredata`，这是 Meson 用于持久化构建配置的数据结构。

**与逆向方法的关联 (举例说明):**

虽然这个文件本身不直接执行逆向操作，但它为 frida 这样的动态 instrumentation 工具的构建过程提供了环境基础。frida 需要在目标设备上运行，而这个文件帮助 Meson 构建出能够在该目标设备上运行的 frida 组件。

*   **交叉编译:**  如果 frida 需要运行在与开发机不同的架构上 (例如，在 x86\_64 的 PC 上开发，但目标是 ARM Android 设备)，这个文件会处理交叉编译的配置。它会读取 cross-compilation 配置文件，其中可能指定了目标架构的编译器、链接器和其他工具的路径。这对于逆向工程师来说至关重要，因为他们经常需要在不同的目标平台上分析和调试软件。

*   **工具链配置:**  逆向工程中常用的工具，如调试器 (lldb, gdb) 或反汇编器 (如包含在 llvm 中的工具)，可能需要在构建时进行配置。虽然这个文件不直接配置这些逆向工具，但它负责构建环境的设置，确保构建过程能够找到和使用这些工具链中的组件 (例如，通过检测 llvm 工具链)。

**涉及二进制底层、Linux/Android 内核及框架的知识 (举例说明):**

*   **CPU 架构检测:**  代码中对不同 CPU 架构的检测和规范化 (例如，将 'i686' 映射到 'x86') 需要对底层硬件有一定的了解。例如，知道 `__i386__` 宏在 x86 架构上的含义。

*   **Windows 架构检测:**  `detect_windows_arch` 函数涉及到 Windows 系统的一些底层概念，例如 WOW64 (Windows 32-bit on Windows 64-bit)，以及如何通过环境变量判断当前环境的实际架构。

*   **内核类型检测:**  `detect_kernel` 函数维护了一个内核名称的映射表，这需要了解不同操作系统的内核命名约定。例如，知道 'darwin' 对应 'xnu' (macOS 内核)。

*   **代码覆盖率工具:**  对 `gcovr`, `lcov`, `llvm-cov` 的检测表明，该构建系统可能需要生成代码覆盖率报告。这些工具会涉及到对编译后的二进制代码进行插桩，并在程序运行时收集执行信息。这与理解程序的二进制结构和执行流程有关。

**逻辑推理 (假设输入与输出):**

假设用户在一个 Linux x86\_64 系统上构建 frida，并且安装了 ninja 和 clang。

*   **输入:**  执行 `meson setup builddir` 命令。
*   **假设输入:** 环境变量中没有显式设置 `NINJA` 或 `CLANG` 的路径。
*   **输出:**
    *   `detect_system()` 会返回 "linux"。
    *   `detect_cpu_family(compilers)` (如果编译器是 clang) 可能会返回 "x86\_64"。
    *   `detect_ninja()` 会在 PATH 中找到 ninja 并返回其路径。
    *   如果安装了 clang，相关的编译器检测函数会找到 clang 的路径。
    *   `Environment` 对象会被创建，并存储这些检测到的信息。

**涉及用户或编程常见的使用错误 (举例说明):**

*   **环境变量设置错误:** 用户可能错误地设置了构建工具的环境变量，例如将 `NINJA` 指向一个不存在的可执行文件，或者设置了错误的路径分隔符。这会导致 `detect_ninja` 等函数找不到工具。

*   **配置文件错误:**  用户可能在 native 或 cross-compilation 配置文件中指定了错误的编译器路径或选项，导致构建过程失败。例如，在 cross-compilation 配置文件中指定了 build 机器的编译器路径，而不是 target 机器的编译器路径。

*   **版本不兼容:**  用户安装了过低版本的构建工具 (例如，旧版本的 ninja)，导致版本检测失败，Meson 可能会报错或发出警告。

**用户操作是如何一步步的到达这里 (调试线索):**

1. **用户尝试配置构建环境:** 用户在 frida 的源代码目录下执行 `meson setup builddir` 命令。
2. **Meson 初始化:** Meson 首先会读取 `meson.build` 文件，然后开始初始化构建环境。
3. **加载 Environment 模块:** Meson 会加载 `mesonbuild/environment.py` 模块。
4. **创建 Environment 实例:** Meson 会创建 `Environment` 类的实例，这个过程中会调用各种 `detect_*` 函数来检测系统信息和工具。
5. **处理配置文件:** 如果存在 native 或 cross-compilation 配置文件，Meson 会读取并解析这些文件，并更新 `Environment` 对象中的配置信息。
6. **存储构建配置:**  检测到的信息和配置选项会被存储在 `coredata` 中，以便后续的构建步骤使用。

**功能归纳 (第 1 部分):**

这个 Python 文件的主要功能是 **负责 Meson 构建系统初始化阶段的环境检测和配置**。它通过检测操作系统、硬件信息、构建工具、处理环境变量和配置文件，为后续的构建过程提供必要的环境信息。这个过程对于确保 frida 能够正确地在目标平台上构建至关重要，特别是当涉及到交叉编译等复杂场景时。它还涉及到对底层操作系统和硬件的理解，以及对常见构建工具和其工作方式的了解。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/environment.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
# Copyright 2012-2020 The Meson development team
# Copyright © 2023 Intel Corporation

from __future__ import annotations

import copy
import itertools
import os, platform, re, sys, shutil
import typing as T
import collections

from . import coredata
from . import mesonlib
from .mesonlib import (
    MesonException, MachineChoice, Popen_safe, PerMachine,
    PerMachineDefaultable, PerThreeMachineDefaultable, split_args, quote_arg, OptionKey,
    search_version, MesonBugException
)
from . import mlog
from .programs import ExternalProgram

from .envconfig import (
    BinaryTable, MachineInfo, Properties, known_cpu_families, CMakeVariables,
)
from . import compilers
from .compilers import (
    is_assembly,
    is_header,
    is_library,
    is_llvm_ir,
    is_object,
    is_source,
)

from functools import lru_cache
from mesonbuild import envconfig

if T.TYPE_CHECKING:
    from configparser import ConfigParser

    from .compilers import Compiler
    from .wrap.wrap import Resolver

    CompilersDict = T.Dict[str, Compiler]


build_filename = 'meson.build'


def _get_env_var(for_machine: MachineChoice, is_cross: bool, var_name: str) -> T.Optional[str]:
    """
    Returns the exact env var and the value.
    """
    candidates = PerMachine(
        # The prefixed build version takes priority, but if we are native
        # compiling we fall back on the unprefixed host version. This
        # allows native builds to never need to worry about the 'BUILD_*'
        # ones.
        ([var_name + '_FOR_BUILD'] if is_cross else [var_name]),
        # Always just the unprefixed host versions
        [var_name]
    )[for_machine]
    for var in candidates:
        value = os.environ.get(var)
        if value is not None:
            break
    else:
        formatted = ', '.join([f'{var!r}' for var in candidates])
        mlog.debug(f'None of {formatted} are defined in the environment, not changing global flags.')
        return None
    mlog.debug(f'Using {var!r} from environment with value: {value!r}')
    return value


def detect_gcovr(gcovr_exe: str = 'gcovr', min_version: str = '3.3', log: bool = False):
    try:
        p, found = Popen_safe([gcovr_exe, '--version'])[0:2]
    except (FileNotFoundError, PermissionError):
        # Doesn't exist in PATH or isn't executable
        return None, None
    found = search_version(found)
    if p.returncode == 0 and mesonlib.version_compare(found, '>=' + min_version):
        if log:
            mlog.log('Found gcovr-{} at {}'.format(found, quote_arg(shutil.which(gcovr_exe))))
        return gcovr_exe, found
    return None, None

def detect_lcov(lcov_exe: str = 'lcov', log: bool = False):
    try:
        p, found = Popen_safe([lcov_exe, '--version'])[0:2]
    except (FileNotFoundError, PermissionError):
        # Doesn't exist in PATH or isn't executable
        return None, None
    found = search_version(found)
    if p.returncode == 0 and found:
        if log:
            mlog.log('Found lcov-{} at {}'.format(found, quote_arg(shutil.which(lcov_exe))))
        return lcov_exe, found
    return None, None

def detect_llvm_cov(suffix: T.Optional[str] = None):
    # If there's a known suffix or forced lack of suffix, use that
    if suffix is not None:
        if suffix == '':
            tool = 'llvm-cov'
        else:
            tool = f'llvm-cov-{suffix}'
        if mesonlib.exe_exists([tool, '--version']):
            return tool
    else:
        # Otherwise guess in the dark
        tools = get_llvm_tool_names('llvm-cov')
        for tool in tools:
            if mesonlib.exe_exists([tool, '--version']):
                return tool
    return None

def compute_llvm_suffix(coredata: coredata.CoreData):
    # Check to see if the user is trying to do coverage for either a C or C++ project
    compilers = coredata.compilers[MachineChoice.BUILD]
    cpp_compiler_is_clang = 'cpp' in compilers and compilers['cpp'].id == 'clang'
    c_compiler_is_clang = 'c' in compilers and compilers['c'].id == 'clang'
    # Extract first the C++ compiler if available. If it's a Clang of some kind, compute the suffix if possible
    if cpp_compiler_is_clang:
        suffix = compilers['cpp'].version.split('.')[0]
        return suffix

    # Then the C compiler, again checking if it's some kind of Clang and computing the suffix
    if c_compiler_is_clang:
        suffix = compilers['c'].version.split('.')[0]
        return suffix

    # Neither compiler is a Clang, or no compilers are for C or C++
    return None

def detect_lcov_genhtml(lcov_exe: str = 'lcov', genhtml_exe: str = 'genhtml'):
    lcov_exe, lcov_version = detect_lcov(lcov_exe)
    if not mesonlib.exe_exists([genhtml_exe, '--version']):
        genhtml_exe = None

    return lcov_exe, lcov_version, genhtml_exe

def find_coverage_tools(coredata: coredata.CoreData) -> T.Tuple[T.Optional[str], T.Optional[str], T.Optional[str], T.Optional[str], T.Optional[str], T.Optional[str]]:
    gcovr_exe, gcovr_version = detect_gcovr()

    llvm_cov_exe = detect_llvm_cov(compute_llvm_suffix(coredata))

    lcov_exe, lcov_version, genhtml_exe = detect_lcov_genhtml()

    return gcovr_exe, gcovr_version, lcov_exe, lcov_version, genhtml_exe, llvm_cov_exe

def detect_ninja(version: str = '1.8.2', log: bool = False) -> T.List[str]:
    r = detect_ninja_command_and_version(version, log)
    return r[0] if r else None

def detect_ninja_command_and_version(version: str = '1.8.2', log: bool = False) -> T.Tuple[T.List[str], str]:
    env_ninja = os.environ.get('NINJA', None)
    for n in [env_ninja] if env_ninja else ['ninja', 'ninja-build', 'samu']:
        prog = ExternalProgram(n, silent=True)
        if not prog.found():
            continue
        try:
            p, found = Popen_safe(prog.command + ['--version'])[0:2]
        except (FileNotFoundError, PermissionError):
            # Doesn't exist in PATH or isn't executable
            continue
        found = found.strip()
        # Perhaps we should add a way for the caller to know the failure mode
        # (not found or too old)
        if p.returncode == 0 and mesonlib.version_compare(found, '>=' + version):
            if log:
                name = os.path.basename(n)
                if name.endswith('-' + found):
                    name = name[0:-1 - len(found)]
                if name == 'ninja-build':
                    name = 'ninja'
                if name == 'samu':
                    name = 'samurai'
                mlog.log('Found {}-{} at {}'.format(name, found,
                         ' '.join([quote_arg(x) for x in prog.command])))
            return (prog.command, found)

def get_llvm_tool_names(tool: str) -> T.List[str]:
    # Ordered list of possible suffixes of LLVM executables to try. Start with
    # base, then try newest back to oldest (3.5 is arbitrary), and finally the
    # devel version. Please note that the development snapshot in Debian does
    # not have a distinct name. Do not move it to the beginning of the list
    # unless it becomes a stable release.
    suffixes = [
        '', # base (no suffix)
        '-18.1', '18.1',
        '-18',  '18',
        '-17',  '17',
        '-16',  '16',
        '-15',  '15',
        '-14',  '14',
        '-13',  '13',
        '-12',  '12',
        '-11',  '11',
        '-10',  '10',
        '-9',   '90',
        '-8',   '80',
        '-7',   '70',
        '-6.0', '60',
        '-5.0', '50',
        '-4.0', '40',
        '-3.9', '39',
        '-3.8', '38',
        '-3.7', '37',
        '-3.6', '36',
        '-3.5', '35',
        '-19',    # Debian development snapshot
        '-devel', # FreeBSD development snapshot
    ]
    names: T.List[str] = []
    for suffix in suffixes:
        names.append(tool + suffix)
    return names

def detect_scanbuild() -> T.List[str]:
    """ Look for scan-build binary on build platform

    First, if a SCANBUILD env variable has been provided, give it precedence
    on all platforms.

    For most platforms, scan-build is found is the PATH contains a binary
    named "scan-build". However, some distribution's package manager (FreeBSD)
    don't. For those, loop through a list of candidates to see if one is
    available.

    Return: a single-element list of the found scan-build binary ready to be
        passed to Popen()
    """
    exelist: T.List[str] = []
    if 'SCANBUILD' in os.environ:
        exelist = split_args(os.environ['SCANBUILD'])

    else:
        tools = get_llvm_tool_names('scan-build')
        for tool in tools:
            which = shutil.which(tool)
            if which is not None:
                exelist = [which]
                break

    if exelist:
        tool = exelist[0]
        if os.path.isfile(tool) and os.access(tool, os.X_OK):
            return [tool]
    return []

def detect_clangformat() -> T.List[str]:
    """ Look for clang-format binary on build platform

    Do the same thing as detect_scanbuild to find clang-format except it
    currently does not check the environment variable.

    Return: a single-element list of the found clang-format binary ready to be
        passed to Popen()
    """
    tools = get_llvm_tool_names('clang-format')
    for tool in tools:
        path = shutil.which(tool)
        if path is not None:
            return [path]
    return []

def detect_windows_arch(compilers: CompilersDict) -> str:
    """
    Detecting the 'native' architecture of Windows is not a trivial task. We
    cannot trust that the architecture that Python is built for is the 'native'
    one because you can run 32-bit apps on 64-bit Windows using WOW64 and
    people sometimes install 32-bit Python on 64-bit Windows.

    We also can't rely on the architecture of the OS itself, since it's
    perfectly normal to compile and run 32-bit applications on Windows as if
    they were native applications. It's a terrible experience to require the
    user to supply a cross-info file to compile 32-bit applications on 64-bit
    Windows. Thankfully, the only way to compile things with Visual Studio on
    Windows is by entering the 'msvc toolchain' environment, which can be
    easily detected.

    In the end, the sanest method is as follows:
    1. Check environment variables that are set by Windows and WOW64 to find out
       if this is x86 (possibly in WOW64), if so use that as our 'native'
       architecture.
    2. If the compiler toolchain target architecture is x86, use that as our
      'native' architecture.
    3. Otherwise, use the actual Windows architecture

    """
    os_arch = mesonlib.windows_detect_native_arch()
    if os_arch == 'x86':
        return os_arch
    # If we're on 64-bit Windows, 32-bit apps can be compiled without
    # cross-compilation. So if we're doing that, just set the native arch as
    # 32-bit and pretend like we're running under WOW64. Else, return the
    # actual Windows architecture that we deduced above.
    for compiler in compilers.values():
        if compiler.id == 'msvc' and (compiler.target in {'x86', '80x86'}):
            return 'x86'
        if compiler.id == 'msvc' and os_arch == 'arm64' and compiler.target == 'x64':
            return 'x86_64'
        if compiler.id == 'clang-cl' and compiler.target == 'x86':
            return 'x86'
        if compiler.id == 'gcc' and compiler.has_builtin_define('__i386__'):
            return 'x86'
    return os_arch

def any_compiler_has_define(compilers: CompilersDict, define: str) -> bool:
    for c in compilers.values():
        try:
            if c.has_builtin_define(define):
                return True
        except mesonlib.MesonException:
            # Ignore compilers that do not support has_builtin_define.
            pass
    return False

def detect_cpu_family(compilers: CompilersDict) -> str:
    """
    Python is inconsistent in its platform module.
    It returns different values for the same cpu.
    For x86 it might return 'x86', 'i686' or somesuch.
    Do some canonicalization.
    """
    if mesonlib.is_windows():
        trial = detect_windows_arch(compilers)
    elif mesonlib.is_freebsd() or mesonlib.is_netbsd() or mesonlib.is_openbsd() or mesonlib.is_qnx() or mesonlib.is_aix():
        trial = platform.processor().lower()
    else:
        trial = platform.machine().lower()
    if trial.startswith('i') and trial.endswith('86'):
        trial = 'x86'
    elif trial == 'bepc':
        trial = 'x86'
    elif trial == 'arm64':
        trial = 'aarch64'
    elif trial.startswith('aarch64'):
        # This can be `aarch64_be`
        trial = 'aarch64'
    elif trial.startswith('arm') or trial.startswith('earm'):
        trial = 'arm'
    elif trial.startswith(('powerpc64', 'ppc64')):
        trial = 'ppc64'
    elif trial.startswith(('powerpc', 'ppc')) or trial in {'macppc', 'power macintosh'}:
        trial = 'ppc'
    elif trial in {'amd64', 'x64', 'i86pc'}:
        trial = 'x86_64'
    elif trial in {'sun4u', 'sun4v'}:
        trial = 'sparc64'
    elif trial.startswith('mips'):
        if '64' not in trial:
            trial = 'mips'
        else:
            trial = 'mips64'
    elif trial in {'ip30', 'ip35'}:
        trial = 'mips64'

    # On Linux (and maybe others) there can be any mixture of 32/64 bit code in
    # the kernel, Python, system, 32-bit chroot on 64-bit host, etc. The only
    # reliable way to know is to check the compiler defines.
    if trial == 'x86_64':
        if any_compiler_has_define(compilers, '__i386__'):
            trial = 'x86'
    elif trial == 'aarch64':
        if any_compiler_has_define(compilers, '__arm__'):
            trial = 'arm'
    # Add more quirks here as bugs are reported. Keep in sync with detect_cpu()
    # below.
    elif trial == 'parisc64':
        # ATM there is no 64 bit userland for PA-RISC. Thus always
        # report it as 32 bit for simplicity.
        trial = 'parisc'
    elif trial == 'ppc':
        # AIX always returns powerpc, check here for 64-bit
        if any_compiler_has_define(compilers, '__64BIT__'):
            trial = 'ppc64'
    # MIPS64 is able to run MIPS32 code natively, so there is a chance that
    # such mixture mentioned above exists.
    elif trial == 'mips64':
        if compilers and not any_compiler_has_define(compilers, '__mips64'):
            trial = 'mips'

    if trial not in known_cpu_families:
        mlog.warning(f'Unknown CPU family {trial!r}, please report this at '
                     'https://github.com/mesonbuild/meson/issues/new with the '
                     'output of `uname -a` and `cat /proc/cpuinfo`')

    return trial

def detect_cpu(compilers: CompilersDict) -> str:
    if mesonlib.is_windows():
        trial = detect_windows_arch(compilers)
    elif mesonlib.is_freebsd() or mesonlib.is_netbsd() or mesonlib.is_openbsd() or mesonlib.is_aix():
        trial = platform.processor().lower()
    else:
        trial = platform.machine().lower()

    if trial in {'amd64', 'x64', 'i86pc'}:
        trial = 'x86_64'
    if trial == 'x86_64':
        # Same check as above for cpu_family
        if any_compiler_has_define(compilers, '__i386__'):
            trial = 'i686' # All 64 bit cpus have at least this level of x86 support.
    elif trial.startswith('aarch64') or trial.startswith('arm64'):
        # Same check as above for cpu_family
        if any_compiler_has_define(compilers, '__arm__'):
            trial = 'arm'
        else:
            # for aarch64_be
            trial = 'aarch64'
    elif trial.startswith('earm'):
        trial = 'arm'
    elif trial == 'e2k':
        # Make more precise CPU detection for Elbrus platform.
        trial = platform.processor().lower()
    elif trial.startswith('mips'):
        if '64' not in trial:
            trial = 'mips'
        else:
            if compilers and not any_compiler_has_define(compilers, '__mips64'):
                trial = 'mips'
            else:
                trial = 'mips64'
    elif trial == 'ppc':
        # AIX always returns powerpc, check here for 64-bit
        if any_compiler_has_define(compilers, '__64BIT__'):
            trial = 'ppc64'

    # Add more quirks here as bugs are reported. Keep in sync with
    # detect_cpu_family() above.
    return trial

KERNEL_MAPPINGS: T.Mapping[str, str] = {'freebsd': 'freebsd',
                                        'openbsd': 'openbsd',
                                        'netbsd': 'netbsd',
                                        'windows': 'nt',
                                        'android': 'linux',
                                        'linux': 'linux',
                                        'cygwin': 'nt',
                                        'darwin': 'xnu',
                                        'dragonfly': 'dragonfly',
                                        'haiku': 'haiku',
                                        }

def detect_kernel(system: str) -> T.Optional[str]:
    if system == 'sunos':
        # Solaris 5.10 uname doesn't support the -o switch, and illumos started
        # with version 5.11 so shortcut the logic to report 'solaris' in such
        # cases where the version is 5.10 or below.
        if mesonlib.version_compare(platform.uname().release, '<=5.10'):
            return 'solaris'
        # This needs to be /usr/bin/uname because gnu-uname could be installed and
        # won't provide the necessary information
        p, out, _ = Popen_safe(['/usr/bin/uname', '-o'])
        if p.returncode != 0:
            raise MesonException('Failed to run "/usr/bin/uname -o"')
        out = out.lower().strip()
        if out not in {'illumos', 'solaris'}:
            mlog.warning(f'Got an unexpected value for kernel on a SunOS derived platform, expcted either "illumos" or "solaris", but got "{out}".'
                         "Please open a Meson issue with the OS you're running and the value detected for your kernel.")
            return None
        return out
    return KERNEL_MAPPINGS.get(system, None)

def detect_subsystem(system: str) -> T.Optional[str]:
    if system == 'darwin':
        return 'macos'
    return system

def detect_system() -> str:
    if sys.platform == 'cygwin':
        return 'cygwin'
    return platform.system().lower()

def detect_msys2_arch() -> T.Optional[str]:
    return os.environ.get('MSYSTEM_CARCH', None)

def detect_machine_info(compilers: T.Optional[CompilersDict] = None) -> MachineInfo:
    """Detect the machine we're running on

    If compilers are not provided, we cannot know as much. None out those
    fields to avoid accidentally depending on partial knowledge. The
    underlying ''detect_*'' method can be called to explicitly use the
    partial information.
    """
    system = detect_system()
    return MachineInfo(
        system,
        detect_cpu_family(compilers) if compilers is not None else None,
        detect_cpu(compilers) if compilers is not None else None,
        sys.byteorder,
        detect_kernel(system),
        detect_subsystem(system))

# TODO make this compare two `MachineInfo`s purely. How important is the
# `detect_cpu_family({})` distinction? It is the one impediment to that.
def machine_info_can_run(machine_info: MachineInfo):
    """Whether we can run binaries for this machine on the current machine.

    Can almost always run 32-bit binaries on 64-bit natively if the host
    and build systems are the same. We don't pass any compilers to
    detect_cpu_family() here because we always want to know the OS
    architecture, not what the compiler environment tells us.
    """
    if machine_info.system != detect_system():
        return False
    true_build_cpu_family = detect_cpu_family({})
    return \
        (machine_info.cpu_family == true_build_cpu_family) or \
        ((true_build_cpu_family == 'x86_64') and (machine_info.cpu_family == 'x86')) or \
        ((true_build_cpu_family == 'mips64') and (machine_info.cpu_family == 'mips')) or \
        ((true_build_cpu_family == 'aarch64') and (machine_info.cpu_family == 'arm'))

class Environment:
    private_dir = 'meson-private'
    log_dir = 'meson-logs'
    info_dir = 'meson-info'

    def __init__(self, source_dir: str, build_dir: str, options: coredata.SharedCMDOptions) -> None:
        self.source_dir = source_dir
        self.build_dir = build_dir
        # Do not try to create build directories when build_dir is none.
        # This reduced mode is used by the --buildoptions introspector
        if build_dir is not None:
            self.scratch_dir = os.path.join(build_dir, Environment.private_dir)
            self.log_dir = os.path.join(build_dir, Environment.log_dir)
            self.info_dir = os.path.join(build_dir, Environment.info_dir)
            os.makedirs(self.scratch_dir, exist_ok=True)
            os.makedirs(self.log_dir, exist_ok=True)
            os.makedirs(self.info_dir, exist_ok=True)
            try:
                self.coredata: coredata.CoreData = coredata.load(self.get_build_dir(), suggest_reconfigure=False)
                self.first_invocation = False
            except FileNotFoundError:
                self.create_new_coredata(options)
            except coredata.MesonVersionMismatchException as e:
                # This is routine, but tell the user the update happened
                mlog.log('Regenerating configuration from scratch:', str(e))
                coredata.read_cmd_line_file(self.build_dir, options)
                self.create_new_coredata(options)
            except MesonException as e:
                # If we stored previous command line options, we can recover from
                # a broken/outdated coredata.
                if os.path.isfile(coredata.get_cmd_line_file(self.build_dir)):
                    mlog.warning('Regenerating configuration from scratch.', fatal=False)
                    mlog.log('Reason:', mlog.red(str(e)))
                    coredata.read_cmd_line_file(self.build_dir, options)
                    self.create_new_coredata(options)
                else:
                    raise MesonException(f'{str(e)} Try regenerating using "meson setup --wipe".')
        else:
            # Just create a fresh coredata in this case
            self.scratch_dir = ''
            self.create_new_coredata(options)

        ## locally bind some unfrozen configuration

        # Stores machine infos, the only *three* machine one because we have a
        # target machine info on for the user (Meson never cares about the
        # target machine.)
        machines: PerThreeMachineDefaultable[MachineInfo] = PerThreeMachineDefaultable()

        # Similar to coredata.compilers, but lower level in that there is no
        # meta data, only names/paths.
        binaries: PerMachineDefaultable[BinaryTable] = PerMachineDefaultable()

        # Misc other properties about each machine.
        properties: PerMachineDefaultable[Properties] = PerMachineDefaultable()

        # CMake toolchain variables
        cmakevars: PerMachineDefaultable[CMakeVariables] = PerMachineDefaultable()

        ## Setup build machine defaults

        # Will be fully initialized later using compilers later.
        machines.build = detect_machine_info()

        # Just uses hard-coded defaults and environment variables. Might be
        # overwritten by a native file.
        binaries.build = BinaryTable()
        properties.build = Properties()

        # Options with the key parsed into an OptionKey type.
        #
        # Note that order matters because of 'buildtype', if it is after
        # 'optimization' and 'debug' keys, it override them.
        self.options: T.MutableMapping[OptionKey, T.Union[str, T.List[str]]] = collections.OrderedDict()

        ## Read in native file(s) to override build machine configuration

        if self.coredata.config_files is not None:
            config = coredata.parse_machine_files(self.coredata.config_files, self.source_dir)
            binaries.build = BinaryTable(config.get('binaries', {}))
            properties.build = Properties(config.get('properties', {}))
            cmakevars.build = CMakeVariables(config.get('cmake', {}))
            self._load_machine_file_options(
                config, properties.build,
                MachineChoice.BUILD if self.coredata.cross_files else MachineChoice.HOST)

        ## Read in cross file(s) to override host machine configuration

        if self.coredata.cross_files:
            config = coredata.parse_machine_files(self.coredata.cross_files, self.source_dir)
            properties.host = Properties(config.get('properties', {}))
            binaries.host = BinaryTable(config.get('binaries', {}))
            cmakevars.host = CMakeVariables(config.get('cmake', {}))
            if 'host_machine' in config:
                machines.host = MachineInfo.from_literal(config['host_machine'])
            if 'target_machine' in config:
                machines.target = MachineInfo.from_literal(config['target_machine'])
            # Keep only per machine options from the native file. The cross
            # file takes precedence over all other options.
            for key, value in list(self.options.items()):
                if self.coredata.is_per_machine_option(key):
                    self.options[key.as_build()] = value
            self._load_machine_file_options(config, properties.host, MachineChoice.HOST)

        ## "freeze" now initialized configuration, and "save" to the class.

        self.machines = machines.default_missing()
        self.binaries = binaries.default_missing()
        self.properties = properties.default_missing()
        self.cmakevars = cmakevars.default_missing()

        # Command line options override those from cross/native files
        self.options.update(options.cmd_line_options)

        # Take default value from env if not set in cross/native files or command line.
        self._set_default_options_from_env()
        self._set_default_binaries_from_env()
        self._set_default_properties_from_env()

        # Warn if the user is using two different ways of setting build-type
        # options that override each other
        bt = OptionKey('buildtype')
        db = OptionKey('debug')
        op = OptionKey('optimization')
        if bt in self.options and (db in self.options or op in self.options):
            mlog.warning('Recommend using either -Dbuildtype or -Doptimization + -Ddebug. '
                         'Using both is redundant since they override each other. '
                         'See: https://mesonbuild.com/Builtin-options.html#build-type-options',
                         fatal=False)

        exe_wrapper = self.lookup_binary_entry(MachineChoice.HOST, 'exe_wrapper')
        if exe_wrapper is not None:
            self.exe_wrapper = ExternalProgram.from_bin_list(self, MachineChoice.HOST, 'exe_wrapper')
        else:
            self.exe_wrapper = None

        self.default_cmake = ['cmake']
        self.default_pkgconfig = ['pkg-config']
        self.wrap_resolver: T.Optional['Resolver'] = None

    def _load_machine_file_options(self, config: 'ConfigParser', properties: Properties, machine: MachineChoice) -> None:
        """Read the contents of a Machine file and put it in the options store."""

        # Look for any options in the deprecated paths section, warn about
        # those, then assign them. They will be overwritten by the ones in the
        # "built-in options" section if they're in both sections.
        paths = config.get('paths')
        if paths:
            mlog.deprecation('The [paths] section is deprecated, use the [built-in options] section instead.')
            for k, v in paths.items():
                self.options[OptionKey.from_string(k).evolve(machine=machine)] = v

        # Next look for compiler options in the "properties" section, this is
        # also deprecated, and these will also be overwritten by the "built-in
        # options" section. We need to remove these from this section, as well.
        deprecated_properties: T.Set[str] = set()
        for lang in compilers.all_languages:
            deprecated_properties.add(lang + '_args')
            deprecated_properties.add(lang + '_link_args')
        for k, v in properties.properties.copy().items():
            if k in deprecated_properties:
                mlog.deprecation(f'{k} in the [properties] section of the machine file is deprecated, use the [built-in options] section.')
                self.options[OptionKey.from_string(k).evolve(machine=machine)] = v
                del properties.properties[k]

        for section, values in config.items():
            if ':' in section:
                subproject, section = section.split(':')
            else:
                subproject = ''
            if section == 'built-in options':
                for k, v in values.items():
                    key = OptionKey.from_string(k)
                    # If we're in the cross file, and there is a `build.foo` warn about that. Later we'll remove it.
                    if machine is MachineChoice.HOST and key.machine is not machine:
                        mlog.deprecation('Setting build machine options in cross files, please use a native file instead, this will be removed in meson 0.60', once=True)
                    if key.subproject:
                        raise MesonException('Do not set subproject options in [built-in options] section, use [subproject:built-in options] instead.')
                    self.options[key.evolve(subproject=subproject, machine=machine)] = v
            elif section == 'project options' and machine is MachineChoice.HOST:
                # Project options are only for the host machine, we don't want
                # to read these from the native file
                for k, v in values.items():
                    # Project options are always for the host machine
                    key = OptionKey.from_string(k)
                    if key.subproject:
                        raise MesonException('Do not set subproject options in [built-in options] section, use [subproject:built-in options] instead.')
                    self.options[key.evolve(subproject=subproject)] = v

    def _set_default_options_from_env(self) -> None:
        opts: T.List[T.Tuple[str, str]] = (
            [(v, f'{k}_args') for k, v in compilers.compilers.CFLAGS_MAPPING.items()] +
            [
                ('PKG_CONFIG_PATH', 'pkg_config_path'),
                ('CMAKE_PREFIX_PATH', 'cmake_prefix_path'),
                ('LDFLAGS', 'ldflags'),
                ('CPPFLAGS', 'cppflags'),
            ]
        )

        env_opts: T.DefaultDict[OptionKey, T.List[str]] = collections.defaultdict(list)

        for (evar, keyname), for_machine in itertools.product(opts, MachineChoice):
            p_env = _get_env_var(for_machine, self.is_cross_build(), evar)
            if p_env is not None:
                # these may contain duplicates, which must be removed, else
                # a duplicates-in-array-option warning arises.
                if keyname == 'cmake_prefix_path':
                    if self.machines[for_machine].is_windows():
                        # Cannot split on ':' on Windows because its in the drive letter
                        _p_env = p_env.split(os.pathsep)
                    else:
                        # https://github.com/mesonbuild/meson/issues/7294
                        _p_env = re.split(r':|;', p_env)
                    p_list = list(mesonlib.OrderedSet(_p_env))
                elif keyname == 'pkg_config_path':
                    p_list = list(mesonlib.OrderedSet(p_env.split(os.pathsep)))
                else:
                    p_list = split_args(p_env)
                p_list = [e for e in p_list if e]  # filter out any empty elements

                # Take env vars only on first invocation, if the env changes when
                # reconfiguring it gets ignored.
                # FIXME: We should remember if we took the value from env to warn
                # if it changes on future invocations.
                if self.first_invocation:
                    if keyname == 'ldflags':
                        key = OptionKey('link_args', machine=for_machine, lang='c')  # needs a language to initialize properly
                        for lang in compilers.compilers.LANGUAGES_USING_LDFLAGS:
                            key = key.evolve(lang=lang)
                            env_opts[key].extend(p_list)
                    elif keyname == 'cppflags':
                        key = OptionKey('env_args', machine=for_machine, lang='c')
                        for lang in compilers.compilers.LANGUAGES_USING_CPPFLAGS:
                            key = key.evolve(lang=lang)
```