Response:
The user wants to understand the functionality of a Python file related to the CUDA compiler within the Frida dynamic instrumentation tool. I need to analyze the code and explain its purpose, especially focusing on its relation to reverse engineering, low-level programming, logical reasoning, common user errors, and debugging.

Here's a breakdown of the code's functionality:

1. **Compiler Definition:** It defines a `CudaCompiler` class that inherits from a generic `Compiler` class. This class represents the NVCC CUDA compiler within the Meson build system.
2. **Flag Handling:** It includes dictionaries (`_FLAG_PASSTHRU_NOARGS`, `_FLAG_LONG2SHORT_WITHARGS`, `_FLAG_SHORT2LONG_WITHARGS`) to manage NVCC compiler flags, mapping long and short options and specifying if they take arguments.
3. **Argument Conversion:** The `_to_host_flags` method is crucial. It translates generic compiler flags (like those used by GCC) into NVCC-specific flags, handling differences in syntax and supported options. It also addresses the way NVCC handles comma-separated lists of arguments.
4. **Sanity Check:** The `sanity_check` method performs a basic compilation and execution test to ensure the CUDA compiler is working correctly. It also tries to detect the available GPU architecture.
5. **Header Symbol Check:** The `has_header_symbol` method checks if a specific symbol is defined in a given header file.
6. **Optimization and Debugging Flags:** It defines dictionaries for mapping optimization levels (`cuda_optimization_args`) and debug flags (`cuda_debug_args`).
7. **Cross-Compilation Support:** It considers cross-compilation scenarios and interacts with an "exe\_wrapper" for running executables on different architectures.

Now, let's address the specific points requested by the user:

*   **Functionality:** Summarize the core functions of the script.
*   **Relation to Reverse Engineering:** Identify areas where the code might be relevant to reverse engineering.
*   **Binary/Kernel/Framework Knowledge:** Point out instances where the code interacts with or requires knowledge of these areas.
*   **Logical Reasoning:** Analyze parts of the code that involve decision-making or conditional logic, providing examples.
*   **User Errors:** Predict common mistakes users might make when using this functionality.
*   **Debugging Path:** Explain how a user might end up interacting with this specific part of Frida.
这是 `frida/subprojects/frida-python/releng/meson/mesonbuild/compilers/cuda.py` 文件的功能归纳：

**核心功能：**

该 Python 文件定义了 `CudaCompiler` 类，用于在 Meson 构建系统中处理 CUDA 代码的编译。它封装了与 NVIDIA 的 CUDA 编译器 `nvcc` 交互的逻辑，使得 Meson 能够理解和使用 CUDA 编译器来构建项目。

**主要功能点包括：**

1. **编译器抽象：** `CudaCompiler` 继承自 `Compiler` 基类，提供了 Meson 构建系统所需的通用编译器接口。
2. **NVCC 命令选项映射：**  维护了多个字典 (`_FLAG_PASSTHRU_NOARGS`, `_FLAG_LONG2SHORT_WITHARGS`, `_FLAG_SHORT2LONG_WITHARGS`)，用于存储 NVCC 编译器的各种命令行选项及其对应的长短格式。这使得 Meson 能够以更通用的方式处理编译器选项，并在内部将其转换为 `nvcc` 可以理解的格式。
3. **编译器标志转换：**  `_to_host_flags` 方法负责将通用的编译器标志（例如 GCC 风格的标志）转换为 NVCC 特定的标志。由于 NVCC 在语法和支持的选项上与 GCC 有差异，这个转换过程至关重要。该方法还处理了 NVCC 对逗号分隔列表参数的特殊解析规则，并提供了转义机制。
4. **编译和链接：**  虽然代码片段中没有直接展示编译和链接的具体执行过程，但该类是 Meson 构建系统中处理 CUDA 代码编译的关键部分。它会被 Meson 调用来生成实际的 `nvcc` 命令。
5. **Sanity 检查：** `sanity_check` 方法会执行一个简单的 CUDA 代码编译和运行测试，以验证 CUDA 编译器是否正确安装和配置。这个测试还会尝试检测本地构建环境的 GPU 架构。
6. **头文件符号检查：** `has_header_symbol` 方法用于检查给定的头文件中是否定义了特定的符号。
7. **优化和调试选项：** 定义了 `cuda_optimization_args` 和 `cuda_debug_args` 字典，用于映射不同的优化级别和调试选项到 NVCC 的命令行参数。
8. **交叉编译支持：**  考虑了交叉编译的场景，并能与 `exe_wrapper` 配合使用，以便在目标平台上运行编译后的代码。

**功能归纳：**

总而言之，`cuda.py` 文件的核心功能是**作为 Meson 构建系统中 CUDA 编译器的接口和适配器**。它负责理解 Meson 的构建指令，并将这些指令转化为 `nvcc` 编译器能够执行的命令，同时处理不同编译器标志之间的转换和兼容性问题，并进行基本的环境检查。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/compilers/cuda.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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