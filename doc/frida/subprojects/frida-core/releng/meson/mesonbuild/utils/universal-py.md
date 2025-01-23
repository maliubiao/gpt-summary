Response:
The user wants a summary of the Python code provided in the file `universal.py`. I need to identify the main functionalities of this module. The prompt also asks to relate the functionalities to reverse engineering, low-level binary operations, Linux/Android kernel/framework knowledge, logical inferences, common user errors, and debugging.

Here's a plan:
1. **Identify Core Functionalities:** Go through the code and group related functions and classes based on their purpose.
2. **Reverse Engineering Relevance:**  Analyze if any function or class directly assists in reverse engineering tasks.
3. **Binary/Kernel/Framework Relevance:** Check for interactions with the operating system, file system, or specific OS features (like process execution).
4. **Logical Inference:** Look for functions that make decisions based on inputs. Provide examples of inputs and expected outputs.
5. **User Errors:**  Think about how a user might misuse these functions and provide examples.
6. **Debugging Context:**  Infer how a user might end up in this specific module during the debugging of Frida.
7. **Summarize Functionality:**  Provide a high-level overview of the module's purpose.
这是 `frida/subprojects/frida-core/releng/meson/mesonbuild/utils/universal.py` 文件的第一部分源代码，主要包含了一系列通用的工具函数和类，用于在 Frida 的构建过程中提供辅助功能。以下是该部分代码功能的归纳：

**核心功能归纳:**

1. **系统和环境信息获取:**
    *   提供了一系列函数来判断当前运行的操作系统类型（`is_windows`, `is_linux`, `is_osx`, `is_android` 等）。
    *   提供了获取 Python 解释器命令 (`python_command`) 和 Meson 构建系统命令 (`get_meson_command`, `set_meson_command`) 的功能。
    *   提供了检测 Windows 系统原生架构 (`windows_detect_native_arch`) 的功能。

2. **版本控制系统 (VCS) 支持:**
    *   提供了与 Git 交互的函数 (`git`, `quiet_git`, `verbose_git`)，用于获取版本信息等。
    *   提供了通用的 VCS 检测机制 (`detect_vcs`)，可以识别 Git、Mercurial、Subversion 和 Bazaar 等版本控制系统。

3. **文件和路径操作:**
    *   定义了 `File` 类来表示源代码或构建生成的文件，并提供获取文件相对路径、绝对路径、后缀名等功能。
    *   提供了文件模式 (`FileMode`) 类，用于处理文件权限设置。
    *   提供了创建临时目录 (`TemporaryDirectoryWinProof`) 的功能，并考虑了 Windows 平台的特殊性。
    *   提供了判断路径是否在根目录下的功能 (`path_is_in_root`).

4. **版本比较:**
    *   定义了 `Version` 类来实现类似 RPM 的版本比较逻辑。
    *   提供了版本比较函数 (`version_compare`, `version_compare_many`, `version_compare_condition_with_min`)。
    *   提供了从文本中搜索版本号的函数 (`search_version`).

5. **进程和命令执行:**
    *   提供了安全执行子进程的函数 (`Popen_safe`, `Popen_safe_logged`)。
    *   提供了检查可执行文件是否存在的功能 (`exe_exists`).

6. **字符串和列表处理:**
    *   提供了将参数列表转换为字符串 (`join_args`) 和将字符串拆分为参数列表 (`split_args`) 的功能。
    *   提供了一系列将不同类型数据转换为列表的函数 (`listify`, `stringlistify`, `typeslistify`, `extract_as_list`).
    *   提供了判断字符串是否为 ASCII 的函数 (`is_ascii_string`).

7. **平台特定操作:**
    *   提供了针对 Darwin (macOS) 平台获取目标文件架构信息的功能 (`darwin_get_object_archs`).

8. **枚举和常量定义:**
    *   定义了 `MachineChoice` 枚举类，用于表示构建机和宿主机。
    *   定义了 `PerMachine` 和 `PerThreeMachine` 等类，用于表示不同机器上的配置信息。

9. **异常处理:**
    *   定义了 `EnvironmentException` 和 `GitException` 异常类。

10. **其他工具函数:**
    *   提供了运行一次性代码的装饰器 (`run_once`).
    *   提供了对文件内容进行替换的功能 (`replace_if_different`, `do_replacement`).
    *   提供了 `OrderedSet` 类，保持元素插入顺序的集合。
    *   提供了 `ProgressBar` 类，用于显示进度条。
    *   提供了加载 pickle 数据的函数 (`pickle_load`).

**与逆向方法的关系及举例说明:**

*   **获取目标文件架构信息 (`darwin_get_object_archs`):** 在逆向工程中，了解目标二进制文件的架构 (如 x86, arm64) 是至关重要的，这决定了你使用的反汇编器、调试器以及分析方法。`darwin_get_object_archs` 可以帮助 Frida 在 macOS 上确定需要注入代码的目标进程的架构。例如，如果要 hook 一个只支持 arm64 架构的 iOS 应用，Frida 需要知道这个信息才能正确地加载和执行 Agent 代码。

*   **执行外部命令 (`Popen_safe`, `quiet_git`):**  逆向工程师常常需要使用各种命令行工具来分析和操作二进制文件。例如，可以使用 `objdump` 或 `readelf` 来查看 ELF 文件的头部信息，或者使用 `otool` 来查看 Mach-O 文件的加载命令。Frida 内部也可能使用这些工具来获取目标进程的信息。例如，在 Android 上，Frida 可能会使用 `adb shell` 执行一些命令来获取设备信息。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明:**

*   **文件模式 (`FileMode`):**  在 Linux 和 Android 系统中，文件权限是重要的安全机制。`FileMode` 类处理的文件权限 (读、写、执行) 直接对应于操作系统底层的权限控制。Frida 在安装自身组件或操作目标进程文件时，可能需要设置特定的文件权限。例如，在 Android 上安装 Frida Server 时，可能需要设置其执行权限。

*   **判断操作系统类型 (`is_linux`, `is_android`):** Frida 是一个跨平台的工具，需要根据不同的操作系统执行不同的操作。例如，在 Linux 上注入代码的方式可能与在 Windows 或 macOS 上不同。判断操作系统类型是进行平台特定操作的基础。

*   **执行子进程 (`Popen_safe`):**  Frida 的很多功能依赖于启动和管理子进程。例如，在 Android 上，Frida Server 通常作为一个独立的进程运行。`Popen_safe` 函数用于安全地执行这些进程，并捕获其输出和错误信息。

**逻辑推理及假设输入与输出:**

*   **`version_compare(vstr1, vstr2)`:**
    *   **假设输入:** `vstr1 = "1.2.3"`, `vstr2 = "1.2.4"`
    *   **输出:** `True` (因为 1.2.3 小于 1.2.4)
    *   **假设输入:** `vstr1 = "1.2"`, `vstr2 = "1.2.0"`
    *   **输出:** `True` (因为 1.2 等于 1.2.0，根据版本比较逻辑)
    *   **假设输入:** `vstr1 = "1.2.3"`, `vstr2 = ">=1.2.0"`
    *   **输出:** `True`

*   **`detect_vcs(source_dir)`:**
    *   **假设输入:** `source_dir` 指向一个包含 `.git` 目录的目录。
    *   **输出:** 一个包含 Git 相关信息的字典，例如 `{'name': 'git', 'cmd': 'git', 'repo_dir': '.git', ...}`。
    *   **假设输入:** `source_dir` 指向一个不包含任何已知 VCS 目录的目录。
    *   **输出:** `None`。

**涉及用户或编程常见的使用错误及举例说明:**

*   **`FileMode` 的 `perms_s_to_bits` 方法:** 用户可能会传入一个不符合格式要求的权限字符串，例如 `"rwxrwr"` (缺少一位)。这将导致 `MesonException` 异常，提示用户权限字符串的格式不正确。

*   **`git` 函数:** 用户可能会在没有安装 Git 的环境下调用 Git 相关函数。这将导致 `AssertionError` 或 `GitException` 异常，因为 `GIT` 变量为 `None`。

*   **`get_compiler_for_source` 函数:** 用户可能会传入一个无法被任何已知的编译器处理的文件类型。这将导致 `MesonException` 异常，提示没有找到合适的编译器。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

Frida 的构建过程使用 Meson 构建系统。当用户执行 `meson build` 命令来构建 Frida 时，Meson 会读取 `meson.build` 文件，并根据其中的指令调用各种构建工具和脚本。

1. **配置阶段:** Meson 在配置阶段会执行各种检查，例如检查系统环境、编译器、依赖库等。`universal.py` 中的函数可能会被调用来获取系统信息 (`is_linux`, `windows_detect_native_arch`)，检查 Git 是否可用 (`shutil.which('git')`)，或者确定 Python 解释器的路径 (`sys.executable`)。

2. **代码生成阶段:**  Meson 可能会调用 `universal.py` 中的函数来生成配置文件。例如，`do_conf_file` 和 `do_conf_str` 函数会使用这里提供的字符串处理和替换工具。

3. **编译和链接阶段:** 虽然这部分代码本身不直接参与编译和链接，但其中定义的 `File` 类用于表示源代码和构建产物，被其他 Meson 模块用于管理文件。

4. **安装阶段:**  在安装 Frida 组件时，`FileMode` 类可能会被用来设置安装文件的权限。

**调试线索:** 如果在 Frida 的构建过程中出现错误，例如：

*   **构建失败，提示找不到 Git:**  可能是 `GIT` 变量为 `None`，需要检查系统是否安装了 Git，以及 `shutil.which('git')` 是否返回了正确的路径。
*   **构建失败，提示文件权限错误:**  可能是 `FileMode` 类处理权限时出现了问题，需要检查传入的权限字符串是否正确。
*   **构建失败，提示找不到编译器:** 可能是 `get_compiler_for_source` 函数抛出了异常，需要检查 Meson 的编译器配置。
*   **构建过程中涉及到版本比较的逻辑错误:**  需要检查 `Version` 类和相关的版本比较函数是否按预期工作。

总之，`universal.py` 作为一个工具库，在 Frida 的构建过程的各个阶段都可能被用到。理解其功能有助于定位和解决构建过程中出现的各种问题。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/utils/universal.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2020 The Meson development team


"""A library of random helper functionality."""

from __future__ import annotations
from pathlib import Path
import argparse
import ast
import enum
import sys
import stat
import time
import abc
import platform, subprocess, operator, os, shlex, shutil, re
import collections
from functools import lru_cache, wraps, total_ordering
from itertools import tee
from tempfile import TemporaryDirectory, NamedTemporaryFile
import typing as T
import textwrap
import pickle
import errno
import json

from mesonbuild import mlog
from .core import MesonException, HoldableObject

if T.TYPE_CHECKING:
    from typing_extensions import Literal, Protocol

    from .._typing import ImmutableListProtocol
    from ..build import ConfigurationData
    from ..coredata import StrOrBytesPath
    from ..environment import Environment
    from ..compilers.compilers import Compiler
    from ..interpreterbase.baseobjects import SubProject

    class _EnvPickleLoadable(Protocol):

        environment: Environment

    class _VerPickleLoadable(Protocol):

        version: str

    # A generic type for pickle_load. This allows any type that has either a
    # .version or a .environment to be passed.
    _PL = T.TypeVar('_PL', bound=T.Union[_EnvPickleLoadable, _VerPickleLoadable])

FileOrString = T.Union['File', str]

_T = T.TypeVar('_T')
_U = T.TypeVar('_U')

__all__ = [
    'GIT',
    'python_command',
    'project_meson_versions',
    'SecondLevelHolder',
    'File',
    'FileMode',
    'GitException',
    'LibType',
    'MachineChoice',
    'EnvironmentException',
    'FileOrString',
    'GitException',
    'OptionKey',
    'dump_conf_header',
    'OptionType',
    'OrderedSet',
    'PerMachine',
    'PerMachineDefaultable',
    'PerThreeMachine',
    'PerThreeMachineDefaultable',
    'ProgressBar',
    'RealPathAction',
    'TemporaryDirectoryWinProof',
    'Version',
    'check_direntry_issues',
    'classify_unity_sources',
    'current_vs_supports_modules',
    'darwin_get_object_archs',
    'default_libdir',
    'default_libexecdir',
    'default_prefix',
    'default_datadir',
    'default_includedir',
    'default_infodir',
    'default_localedir',
    'default_mandir',
    'default_sbindir',
    'default_sysconfdir',
    'detect_subprojects',
    'detect_vcs',
    'do_conf_file',
    'do_conf_str',
    'do_replacement',
    'exe_exists',
    'expand_arguments',
    'extract_as_list',
    'first',
    'generate_list',
    'get_compiler_for_source',
    'get_filenames_templates_dict',
    'get_variable_regex',
    'get_wine_shortpath',
    'git',
    'has_path_sep',
    'is_aix',
    'is_android',
    'is_ascii_string',
    'is_cygwin',
    'is_debianlike',
    'is_dragonflybsd',
    'is_freebsd',
    'is_haiku',
    'is_hurd',
    'is_irix',
    'is_linux',
    'is_netbsd',
    'is_openbsd',
    'is_osx',
    'is_qnx',
    'is_sunos',
    'is_windows',
    'is_wsl',
    'iter_regexin_iter',
    'join_args',
    'listify',
    'listify_array_value',
    'partition',
    'path_is_in_root',
    'pickle_load',
    'Popen_safe',
    'Popen_safe_logged',
    'quiet_git',
    'quote_arg',
    'relative_to_if_possible',
    'relpath',
    'replace_if_different',
    'run_once',
    'get_meson_command',
    'set_meson_command',
    'split_args',
    'stringlistify',
    'substitute_values',
    'substring_is_in_list',
    'typeslistify',
    'verbose_git',
    'version_compare',
    'version_compare_condition_with_min',
    'version_compare_many',
    'search_version',
    'windows_detect_native_arch',
    'windows_proof_rm',
    'windows_proof_rmtree',
]


# TODO: this is such a hack, this really should be either in coredata or in the
# interpreter
# {subproject: project_meson_version}
project_meson_versions: T.DefaultDict[str, str] = collections.defaultdict(str)


from glob import glob

if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    # using a PyInstaller bundle, e.g. the MSI installed executable
    python_command = [sys.executable, 'runpython']
else:
    python_command = [sys.executable]
_meson_command: T.Optional['ImmutableListProtocol[str]'] = None


class EnvironmentException(MesonException):
    '''Exceptions thrown while processing and creating the build environment'''

class GitException(MesonException):
    def __init__(self, msg: str, output: T.Optional[str] = None):
        super().__init__(msg)
        self.output = output.strip() if output else ''

GIT = shutil.which('git')
def git(cmd: T.List[str], workingdir: StrOrBytesPath, check: bool = False, **kwargs: T.Any) -> T.Tuple[subprocess.Popen[str], str, str]:
    assert GIT is not None, 'Callers should make sure it exists'
    cmd = [GIT, *cmd]
    p, o, e = Popen_safe(cmd, cwd=workingdir, **kwargs)
    if check and p.returncode != 0:
        raise GitException('Git command failed: ' + str(cmd), e)
    return p, o, e

def quiet_git(cmd: T.List[str], workingdir: StrOrBytesPath, check: bool = False) -> T.Tuple[bool, str]:
    if not GIT:
        m = 'Git program not found.'
        if check:
            raise GitException(m)
        return False, m
    p, o, e = git(cmd, workingdir, check)
    if p.returncode != 0:
        return False, e
    return True, o

def verbose_git(cmd: T.List[str], workingdir: StrOrBytesPath, check: bool = False) -> bool:
    if not GIT:
        m = 'Git program not found.'
        if check:
            raise GitException(m)
        return False
    p, _, _ = git(cmd, workingdir, check, stdout=None, stderr=None)
    return p.returncode == 0

def set_meson_command(mainfile: str) -> None:
    global _meson_command  # pylint: disable=global-statement
    # On UNIX-like systems `meson` is a Python script
    # On Windows `meson` and `meson.exe` are wrapper exes
    if not mainfile.endswith('.py'):
        _meson_command = [mainfile]
    elif os.path.isabs(mainfile) and mainfile.endswith('mesonmain.py'):
        # Can't actually run meson with an absolute path to mesonmain.py, it must be run as -m mesonbuild.mesonmain
        _meson_command = python_command + ['-m', 'mesonbuild.mesonmain']
    else:
        # Either run uninstalled, or full path to meson-script.py
        _meson_command = python_command + [mainfile]
    # We print this value for unit tests.
    if 'MESON_COMMAND_TESTS' in os.environ:
        mlog.log(f'meson_command is {_meson_command!r}')


def get_meson_command() -> T.Optional['ImmutableListProtocol[str]']:
    return _meson_command


def is_ascii_string(astring: T.Union[str, bytes]) -> bool:
    try:
        if isinstance(astring, str):
            astring.encode('ascii')
        elif isinstance(astring, bytes):
            astring.decode('ascii')
    except UnicodeDecodeError:
        return False
    return True


def check_direntry_issues(direntry_array: T.Union[T.Iterable[T.Union[str, bytes]], str, bytes]) -> None:
    import locale
    # Warn if the locale is not UTF-8. This can cause various unfixable issues
    # such as os.stat not being able to decode filenames with unicode in them.
    # There is no way to reset both the preferred encoding and the filesystem
    # encoding, so we can just warn about it.
    e = locale.getpreferredencoding()
    if e.upper() != 'UTF-8' and not is_windows():
        if isinstance(direntry_array, (str, bytes)):
            direntry_array = [direntry_array]
        for de in direntry_array:
            if is_ascii_string(de):
                continue
            mlog.warning(textwrap.dedent(f'''
                You are using {e!r} which is not a Unicode-compatible
                locale but you are trying to access a file system entry called {de!r} which is
                not pure ASCII. This may cause problems.
                '''))

class SecondLevelHolder(HoldableObject, metaclass=abc.ABCMeta):
    ''' A second level object holder. The primary purpose
        of such objects is to hold multiple objects with one
        default option. '''

    @abc.abstractmethod
    def get_default_object(self) -> HoldableObject: ...

class FileMode:
    # The first triad is for owner permissions, the second for group permissions,
    # and the third for others (everyone else).
    # For the 1st character:
    #  'r' means can read
    #  '-' means not allowed
    # For the 2nd character:
    #  'w' means can write
    #  '-' means not allowed
    # For the 3rd character:
    #  'x' means can execute
    #  's' means can execute and setuid/setgid is set (owner/group triads only)
    #  'S' means cannot execute and setuid/setgid is set (owner/group triads only)
    #  't' means can execute and sticky bit is set ("others" triads only)
    #  'T' means cannot execute and sticky bit is set ("others" triads only)
    #  '-' means none of these are allowed
    #
    # The meanings of 'rwx' perms is not obvious for directories; see:
    # https://www.hackinglinuxexposed.com/articles/20030424.html
    #
    # For information on this notation such as setuid/setgid/sticky bits, see:
    # https://en.wikipedia.org/wiki/File_system_permissions#Symbolic_notation
    symbolic_perms_regex = re.compile('[r-][w-][xsS-]' # Owner perms
                                      '[r-][w-][xsS-]' # Group perms
                                      '[r-][w-][xtT-]') # Others perms

    def __init__(self, perms: T.Optional[str] = None, owner: T.Union[str, int, None] = None,
                 group: T.Union[str, int, None] = None):
        self.perms_s = perms
        self.perms = self.perms_s_to_bits(perms)
        self.owner = owner
        self.group = group

    def __repr__(self) -> str:
        ret = '<FileMode: {!r} owner={} group={}'
        return ret.format(self.perms_s, self.owner, self.group)

    @classmethod
    def perms_s_to_bits(cls, perms_s: T.Optional[str]) -> int:
        '''
        Does the opposite of stat.filemode(), converts strings of the form
        'rwxr-xr-x' to st_mode enums which can be passed to os.chmod()
        '''
        if perms_s is None:
            # No perms specified, we will not touch the permissions
            return -1
        eg = 'rwxr-xr-x'
        if not isinstance(perms_s, str):
            raise MesonException(f'Install perms must be a string. For example, {eg!r}')
        if len(perms_s) != 9 or not cls.symbolic_perms_regex.match(perms_s):
            raise MesonException(f'File perms {perms_s!r} must be exactly 9 chars. For example, {eg!r}')
        perms = 0
        # Owner perms
        if perms_s[0] == 'r':
            perms |= stat.S_IRUSR
        if perms_s[1] == 'w':
            perms |= stat.S_IWUSR
        if perms_s[2] == 'x':
            perms |= stat.S_IXUSR
        elif perms_s[2] == 'S':
            perms |= stat.S_ISUID
        elif perms_s[2] == 's':
            perms |= stat.S_IXUSR
            perms |= stat.S_ISUID
        # Group perms
        if perms_s[3] == 'r':
            perms |= stat.S_IRGRP
        if perms_s[4] == 'w':
            perms |= stat.S_IWGRP
        if perms_s[5] == 'x':
            perms |= stat.S_IXGRP
        elif perms_s[5] == 'S':
            perms |= stat.S_ISGID
        elif perms_s[5] == 's':
            perms |= stat.S_IXGRP
            perms |= stat.S_ISGID
        # Others perms
        if perms_s[6] == 'r':
            perms |= stat.S_IROTH
        if perms_s[7] == 'w':
            perms |= stat.S_IWOTH
        if perms_s[8] == 'x':
            perms |= stat.S_IXOTH
        elif perms_s[8] == 'T':
            perms |= stat.S_ISVTX
        elif perms_s[8] == 't':
            perms |= stat.S_IXOTH
            perms |= stat.S_ISVTX
        return perms

dot_C_dot_H_warning = """You are using .C or .H files in your project. This is deprecated.
         Currently, Meson treats this as C++ code, but they
            used to be treated as C code.
         Note that the situation is a bit more complex if you are using the
         Visual Studio compiler, as it treats .C files as C code, unless you add
         the /TP compiler flag, but this is unreliable.
         See https://github.com/mesonbuild/meson/pull/8747 for the discussions."""
class File(HoldableObject):
    def __init__(self, is_built: bool, subdir: str, fname: str):
        if fname.endswith(".C") or fname.endswith(".H"):
            mlog.warning(dot_C_dot_H_warning, once=True)
        self.is_built = is_built
        self.subdir = subdir
        self.fname = fname
        self.hash = hash((is_built, subdir, fname))

    def __str__(self) -> str:
        return self.relative_name()

    def __repr__(self) -> str:
        ret = '<File: {0}'
        if not self.is_built:
            ret += ' (not built)'
        ret += '>'
        return ret.format(self.relative_name())

    @staticmethod
    @lru_cache(maxsize=None)
    def from_source_file(source_root: str, subdir: str, fname: str) -> 'File':
        if not os.path.isfile(os.path.join(source_root, subdir, fname)):
            raise MesonException(f'File {fname} does not exist.')
        return File(False, subdir, fname)

    @staticmethod
    def from_built_file(subdir: str, fname: str) -> 'File':
        return File(True, subdir, fname)

    @staticmethod
    def from_built_relative(relative: str) -> 'File':
        dirpart, fnamepart = os.path.split(relative)
        return File(True, dirpart, fnamepart)

    @staticmethod
    def from_absolute_file(fname: str) -> 'File':
        return File(False, '', fname)

    @lru_cache(maxsize=None)
    def rel_to_builddir(self, build_to_src: str) -> str:
        if self.is_built:
            return self.relative_name()
        else:
            return os.path.join(build_to_src, self.subdir, self.fname)

    @lru_cache(maxsize=None)
    def absolute_path(self, srcdir: str, builddir: str) -> str:
        absdir = srcdir
        if self.is_built:
            absdir = builddir
        return os.path.join(absdir, self.relative_name())

    @property
    def suffix(self) -> str:
        return os.path.splitext(self.fname)[1][1:].lower()

    def endswith(self, ending: T.Union[str, T.Tuple[str, ...]]) -> bool:
        return self.fname.endswith(ending)

    def split(self, s: str, maxsplit: int = -1) -> T.List[str]:
        return self.fname.split(s, maxsplit=maxsplit)

    def rsplit(self, s: str, maxsplit: int = -1) -> T.List[str]:
        return self.fname.rsplit(s, maxsplit=maxsplit)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, File):
            return NotImplemented
        if self.hash != other.hash:
            return False
        return (self.fname, self.subdir, self.is_built) == (other.fname, other.subdir, other.is_built)

    def __hash__(self) -> int:
        return self.hash

    @lru_cache(maxsize=None)
    def relative_name(self) -> str:
        return os.path.join(self.subdir, self.fname)


def get_compiler_for_source(compilers: T.Iterable['Compiler'], src: 'FileOrString') -> 'Compiler':
    """Given a set of compilers and a source, find the compiler for that source type."""
    for comp in compilers:
        if comp.can_compile(src):
            return comp
    raise MesonException(f'No specified compiler can handle file {src!s}')


def classify_unity_sources(compilers: T.Iterable['Compiler'], sources: T.Sequence['FileOrString']) -> T.Dict['Compiler', T.List['FileOrString']]:
    compsrclist: T.Dict['Compiler', T.List['FileOrString']] = {}
    for src in sources:
        comp = get_compiler_for_source(compilers, src)
        if comp not in compsrclist:
            compsrclist[comp] = [src]
        else:
            compsrclist[comp].append(src)
    return compsrclist


class MachineChoice(enum.IntEnum):

    """Enum class representing one of the two abstract machine names used in
    most places: the build, and host, machines.
    """

    BUILD = 0
    HOST = 1

    def __str__(self) -> str:
        return f'{self.get_lower_case_name()} machine'

    def get_lower_case_name(self) -> str:
        return PerMachine('build', 'host')[self]

    def get_prefix(self) -> str:
        return PerMachine('build.', '')[self]


class PerMachine(T.Generic[_T]):
    def __init__(self, build: _T, host: _T) -> None:
        self.build = build
        self.host = host

    def __getitem__(self, machine: MachineChoice) -> _T:
        return {
            MachineChoice.BUILD:  self.build,
            MachineChoice.HOST:   self.host,
        }[machine]

    def __setitem__(self, machine: MachineChoice, val: _T) -> None:
        setattr(self, machine.get_lower_case_name(), val)

    def miss_defaulting(self) -> "PerMachineDefaultable[T.Optional[_T]]":
        """Unset definition duplicated from their previous to None

        This is the inverse of ''default_missing''. By removing defaulted
        machines, we can elaborate the original and then redefault them and thus
        avoid repeating the elaboration explicitly.
        """
        unfreeze: PerMachineDefaultable[T.Optional[_T]] = PerMachineDefaultable()
        unfreeze.build = self.build
        unfreeze.host = self.host
        if unfreeze.host == unfreeze.build:
            unfreeze.host = None
        return unfreeze

    def assign(self, build: _T, host: _T) -> None:
        self.build = build
        self.host = host

    def __repr__(self) -> str:
        return f'PerMachine({self.build!r}, {self.host!r})'


class PerThreeMachine(PerMachine[_T]):
    """Like `PerMachine` but includes `target` too.

    It turns out just one thing do we need track the target machine. There's no
    need to computer the `target` field so we don't bother overriding the
    `__getitem__`/`__setitem__` methods.
    """
    def __init__(self, build: _T, host: _T, target: _T) -> None:
        super().__init__(build, host)
        self.target = target

    def miss_defaulting(self) -> "PerThreeMachineDefaultable[T.Optional[_T]]":
        """Unset definition duplicated from their previous to None

        This is the inverse of ''default_missing''. By removing defaulted
        machines, we can elaborate the original and then redefault them and thus
        avoid repeating the elaboration explicitly.
        """
        unfreeze: PerThreeMachineDefaultable[T.Optional[_T]] = PerThreeMachineDefaultable()
        unfreeze.build = self.build
        unfreeze.host = self.host
        unfreeze.target = self.target
        if unfreeze.target == unfreeze.host:
            unfreeze.target = None
        if unfreeze.host == unfreeze.build:
            unfreeze.host = None
        return unfreeze

    def matches_build_machine(self, machine: MachineChoice) -> bool:
        return self.build == self[machine]

    def __repr__(self) -> str:
        return f'PerThreeMachine({self.build!r}, {self.host!r}, {self.target!r})'


class PerMachineDefaultable(PerMachine[T.Optional[_T]]):
    """Extends `PerMachine` with the ability to default from `None`s.
    """
    def __init__(self, build: T.Optional[_T] = None, host: T.Optional[_T] = None) -> None:
        super().__init__(build, host)

    def default_missing(self) -> "PerMachine[_T]":
        """Default host to build

        This allows just specifying nothing in the native case, and just host in the
        cross non-compiler case.
        """
        freeze = PerMachine(self.build, self.host)
        if freeze.host is None:
            freeze.host = freeze.build
        return freeze

    def __repr__(self) -> str:
        return f'PerMachineDefaultable({self.build!r}, {self.host!r})'

    @classmethod
    def default(cls, is_cross: bool, build: _T, host: _T) -> PerMachine[_T]:
        """Easy way to get a defaulted value

        This allows simplifying the case where you can control whether host and
        build are separate or not with a boolean. If the is_cross value is set
        to true then the optional host value will be used, otherwise the host
        will be set to the build value.
        """
        m = cls(build)
        if is_cross:
            m.host = host
        return m.default_missing()


class PerThreeMachineDefaultable(PerMachineDefaultable[T.Optional[_T]], PerThreeMachine[T.Optional[_T]]):
    """Extends `PerThreeMachine` with the ability to default from `None`s.
    """
    def __init__(self, build: T.Optional[_T] = None, host: T.Optional[_T] = None, target: T.Optional[_T] = None) -> None:
        PerThreeMachine.__init__(self, build, host, target)

    def default_missing(self) -> "PerThreeMachine[T.Optional[_T]]":
        """Default host to build and target to host.

        This allows just specifying nothing in the native case, just host in the
        cross non-compiler case, and just target in the native-built
        cross-compiler case.
        """
        freeze = PerThreeMachine(self.build, self.host, self.target)
        if freeze.host is None:
            freeze.host = freeze.build
        if freeze.target is None:
            freeze.target = freeze.host
        return freeze

    def __repr__(self) -> str:
        return f'PerThreeMachineDefaultable({self.build!r}, {self.host!r}, {self.target!r})'


def is_sunos() -> bool:
    return platform.system().lower() == 'sunos'


def is_osx() -> bool:
    return platform.system().lower() == 'darwin'


def is_linux() -> bool:
    return platform.system().lower() == 'linux'


def is_android() -> bool:
    return platform.system().lower() == 'android'


def is_haiku() -> bool:
    return platform.system().lower() == 'haiku'


def is_openbsd() -> bool:
    return platform.system().lower() == 'openbsd'


def is_windows() -> bool:
    platname = platform.system().lower()
    return platname == 'windows'

def is_wsl() -> bool:
    return is_linux() and 'microsoft' in platform.release().lower()

def is_cygwin() -> bool:
    return sys.platform == 'cygwin'


def is_debianlike() -> bool:
    return os.path.isfile('/etc/debian_version')


def is_dragonflybsd() -> bool:
    return platform.system().lower() == 'dragonfly'


def is_netbsd() -> bool:
    return platform.system().lower() == 'netbsd'


def is_freebsd() -> bool:
    return platform.system().lower() == 'freebsd'

def is_irix() -> bool:
    return platform.system().startswith('irix')

def is_hurd() -> bool:
    return platform.system().lower() == 'gnu'

def is_qnx() -> bool:
    return platform.system().lower() == 'qnx'

def is_aix() -> bool:
    return platform.system().lower() == 'aix'

def exe_exists(arglist: T.List[str]) -> bool:
    try:
        if subprocess.run(arglist, timeout=10).returncode == 0:
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return False


@lru_cache(maxsize=None)
def darwin_get_object_archs(objpath: str) -> 'ImmutableListProtocol[str]':
    '''
    For a specific object (executable, static library, dylib, etc), run `lipo`
    to fetch the list of archs supported by it. Supports both thin objects and
    'fat' objects.
    '''
    _, stdo, stderr = Popen_safe(['lipo', '-info', objpath])
    if not stdo:
        mlog.debug(f'lipo {objpath}: {stderr}')
        return None
    stdo = stdo.rsplit(': ', 1)[1]

    # Convert from lipo-style archs to meson-style CPUs
    map_arch = {
        'i386': 'x86',
        'arm64': 'aarch64',
        'arm64e': 'aarch64',
        'ppc7400': 'ppc',
        'ppc970': 'ppc',
    }
    lipo_archs = stdo.split()
    meson_archs = [map_arch.get(lipo_arch, lipo_arch) for lipo_arch in lipo_archs]

    # Add generic name for armv7 and armv7s
    if 'armv7' in stdo:
        meson_archs.append('arm')

    return meson_archs

def windows_detect_native_arch() -> str:
    """
    The architecture of Windows itself: x86, amd64 or arm64
    """
    if sys.platform != 'win32':
        return ''
    try:
        import ctypes
        process_arch = ctypes.c_ushort()
        native_arch = ctypes.c_ushort()
        kernel32 = ctypes.windll.kernel32
        process = ctypes.c_void_p(kernel32.GetCurrentProcess())
        # This is the only reliable way to detect an arm system if we are an x86/x64 process being emulated
        if kernel32.IsWow64Process2(process, ctypes.byref(process_arch), ctypes.byref(native_arch)):
            # https://docs.microsoft.com/en-us/windows/win32/sysinfo/image-file-machine-constants
            if native_arch.value == 0x8664:
                return 'amd64'
            elif native_arch.value == 0x014C:
                return 'x86'
            elif native_arch.value == 0xAA64:
                return 'arm64'
            elif native_arch.value == 0x01C4:
                return 'arm'
    except (OSError, AttributeError):
        pass
    # These env variables are always available. See:
    # https://msdn.microsoft.com/en-us/library/aa384274(VS.85).aspx
    # https://blogs.msdn.microsoft.com/david.wang/2006/03/27/howto-detect-process-bitness/
    arch = os.environ.get('PROCESSOR_ARCHITEW6432', '').lower()
    if not arch:
        try:
            # If this doesn't exist, something is messing with the environment
            arch = os.environ['PROCESSOR_ARCHITECTURE'].lower()
        except KeyError:
            raise EnvironmentException('Unable to detect native OS architecture')
    return arch

def detect_vcs(source_dir: T.Union[str, Path]) -> T.Optional[T.Dict[str, str]]:
    vcs_systems = [
        {
            'name': 'git',
            'cmd': 'git',
            'repo_dir': '.git',
            'get_rev': 'git describe --dirty=+ --always',
            'rev_regex': '(.*)',
            'dep': '.git/logs/HEAD'
        },
        {
            'name': 'mercurial',
            'cmd': 'hg',
            'repo_dir': '.hg',
            'get_rev': 'hg id -i',
            'rev_regex': '(.*)',
            'dep': '.hg/dirstate'
        },
        {
            'name': 'subversion',
            'cmd': 'svn',
            'repo_dir': '.svn',
            'get_rev': 'svn info',
            'rev_regex': 'Revision: (.*)',
            'dep': '.svn/wc.db'
        },
        {
            'name': 'bazaar',
            'cmd': 'bzr',
            'repo_dir': '.bzr',
            'get_rev': 'bzr revno',
            'rev_regex': '(.*)',
            'dep': '.bzr'
        },
    ]
    if isinstance(source_dir, str):
        source_dir = Path(source_dir)

    parent_paths_and_self = collections.deque(source_dir.parents)
    # Prepend the source directory to the front so we can check it;
    # source_dir.parents doesn't include source_dir
    parent_paths_and_self.appendleft(source_dir)
    for curdir in parent_paths_and_self:
        for vcs in vcs_systems:
            if Path.is_dir(curdir.joinpath(vcs['repo_dir'])) and shutil.which(vcs['cmd']):
                vcs['wc_dir'] = str(curdir)
                return vcs
    return None

def current_vs_supports_modules() -> bool:
    vsver = os.environ.get('VSCMD_VER', '')
    nums = vsver.split('.', 2)
    major = int(nums[0])
    if major >= 17:
        return True
    if major == 16 and int(nums[1]) >= 10:
        return True
    return vsver.startswith('16.9.0') and '-pre.' in vsver

# a helper class which implements the same version ordering as RPM
class Version:
    def __init__(self, s: str) -> None:
        self._s = s

        # split into numeric, alphabetic and non-alphanumeric sequences
        sequences1 = re.finditer(r'(\d+|[a-zA-Z]+|[^a-zA-Z\d]+)', s)

        # non-alphanumeric separators are discarded
        sequences2 = [m for m in sequences1 if not re.match(r'[^a-zA-Z\d]+', m.group(1))]

        # numeric sequences are converted from strings to ints
        sequences3 = [int(m.group(1)) if m.group(1).isdigit() else m.group(1) for m in sequences2]

        self._v = sequences3

    def __str__(self) -> str:
        return '{} (V={})'.format(self._s, str(self._v))

    def __repr__(self) -> str:
        return f'<Version: {self._s}>'

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Version):
            return self.__cmp(other, operator.lt)
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, Version):
            return self.__cmp(other, operator.gt)
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, Version):
            return self.__cmp(other, operator.le)
        return NotImplemented

    def __ge__(self, other: object) -> bool:
        if isinstance(other, Version):
            return self.__cmp(other, operator.ge)
        return NotImplemented

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Version):
            return self._v == other._v
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        if isinstance(other, Version):
            return self._v != other._v
        return NotImplemented

    def __cmp(self, other: 'Version', comparator: T.Callable[[T.Any, T.Any], bool]) -> bool:
        # compare each sequence in order
        for ours, theirs in zip(self._v, other._v):
            # sort a non-digit sequence before a digit sequence
            ours_is_int = isinstance(ours, int)
            theirs_is_int = isinstance(theirs, int)
            if ours_is_int != theirs_is_int:
                return comparator(ours_is_int, theirs_is_int)

            if ours != theirs:
                return comparator(ours, theirs)

        # if equal length, all components have matched, so equal
        # otherwise, the version with a suffix remaining is greater
        return comparator(len(self._v), len(other._v))


def _version_extract_cmpop(vstr2: str) -> T.Tuple[T.Callable[[T.Any, T.Any], bool], str]:
    if vstr2.startswith('>='):
        cmpop = operator.ge
        vstr2 = vstr2[2:]
    elif vstr2.startswith('<='):
        cmpop = operator.le
        vstr2 = vstr2[2:]
    elif vstr2.startswith('!='):
        cmpop = operator.ne
        vstr2 = vstr2[2:]
    elif vstr2.startswith('=='):
        cmpop = operator.eq
        vstr2 = vstr2[2:]
    elif vstr2.startswith('='):
        cmpop = operator.eq
        vstr2 = vstr2[1:]
    elif vstr2.startswith('>'):
        cmpop = operator.gt
        vstr2 = vstr2[1:]
    elif vstr2.startswith('<'):
        cmpop = operator.lt
        vstr2 = vstr2[1:]
    else:
        cmpop = operator.eq

    return (cmpop, vstr2)


def version_compare(vstr1: str, vstr2: str) -> bool:
    (cmpop, vstr2) = _version_extract_cmpop(vstr2)
    return cmpop(Version(vstr1), Version(vstr2))


def version_compare_many(vstr1: str, conditions: T.Union[str, T.Iterable[str]]) -> T.Tuple[bool, T.List[str], T.List[str]]:
    if isinstance(conditions, str):
        conditions = [conditions]
    found: T.List[str] = []
    not_found: T.List[str] = []
    for req in conditions:
        if not version_compare(vstr1, req):
            not_found.append(req)
        else:
            found.append(req)
    return not not_found, not_found, found


# determine if the minimum version satisfying the condition |condition| exceeds
# the minimum version for a feature |minimum|
def version_compare_condition_with_min(condition: str, minimum: str) -> bool:
    if condition.startswith('>='):
        cmpop = operator.le
        condition = condition[2:]
    elif condition.startswith('<='):
        return False
    elif condition.startswith('!='):
        return False
    elif condition.startswith('=='):
        cmpop = operator.le
        condition = condition[2:]
    elif condition.startswith('='):
        cmpop = operator.le
        condition = condition[1:]
    elif condition.startswith('>'):
        cmpop = operator.lt
        condition = condition[1:]
    elif condition.startswith('<'):
        return False
    else:
        cmpop = operator.le

    # Declaring a project(meson_version: '>=0.46') and then using features in
    # 0.46.0 is valid, because (knowing the meson versioning scheme) '0.46.0' is
    # the lowest version which satisfies the constraint '>=0.46'.
    #
    # But this will fail here, because the minimum version required by the
    # version constraint ('0.46') is strictly less (in our version comparison)
    # than the minimum version needed for the feature ('0.46.0').
    #
    # Map versions in the constraint of the form '0.46' to '0.46.0', to embed
    # this knowledge of the meson versioning scheme.
    condition = condition.strip()
    if re.match(r'^\d+.\d+$', condition):
        condition += '.0'

    return T.cast('bool', cmpop(Version(minimum), Version(condition)))

def search_version(text: str) -> str:
    # Usually of the type 4.1.4 but compiler output may contain
    # stuff like this:
    # (Sourcery CodeBench Lite 2014.05-29) 4.8.3 20140320 (prerelease)
    # Limiting major version number to two digits seems to work
    # thus far. When we get to GCC 100, this will break, but
    # if we are still relevant whe
```