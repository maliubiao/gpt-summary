Response:
The user wants a summary of the Python code provided. I need to identify the core functionalities of this module. The module name "universal.py" suggests it contains general utility functions.

Here's a breakdown of the code's functionality:

1. **Version Control System (VCS) Handling**:  Functions to detect and interact with Git, including executing Git commands and checking for Git's presence.
2. **Operating System Detection**: Functions to determine the underlying operating system (Linux, Windows, macOS, etc.).
3. **File Handling**:  A `File` class to represent source and build files, along with functions to manipulate file paths and permissions (`FileMode`).
4. **String and List Manipulation**: Utility functions for converting strings to lists, quoting arguments, and performing string comparisons.
5. **Version Comparison**: A `Version` class and associated functions for comparing software versions, supporting various comparison operators.
6. **Process Execution**: Functions for running subprocesses safely and logging their output.
7. **Compiler Handling**: Functions to identify the correct compiler for a given source file.
8. **Data Structures**: Custom data structures like `OrderedSet` and enums for representing machine types (`MachineChoice`).
9. **Path Manipulation**: Functions for creating relative paths and checking if a path is within a root directory.
10. **Configuration Data**: Functions for dumping configuration headers.
11. **Error Handling**: Custom exception classes like `GitException` and `EnvironmentException`.
12. **Platform-Specific Functionality**: Functions tailored for specific platforms, such as detecting the architecture on Windows and getting object architectures on macOS.
13. **Pickling**: Functions for safely loading pickled data.

Now, let's connect these functionalities to the specific requirements in the prompt.
这是 `frida` 动态 instrumentation 工具中位于 `frida/subprojects/frida-clr/releng/meson/mesonbuild/utils/` 目录下的 `universal.py` 文件的源代码。这个文件正如其名，包含了一系列通用的辅助功能。

**功能归纳：**

该文件的主要功能是提供各种通用的工具函数和类，用于支持 `Meson` 构建系统的运行和管理，这些功能涵盖了以下几个方面：

1. **版本控制系统（VCS）集成**:
   - 提供了检测项目是否使用了版本控制系统（如 Git, Mercurial, Subversion, Bazaar）的功能 (`detect_vcs`)。
   - 封装了执行 Git 命令的函数 (`git`, `quiet_git`, `verbose_git`)，并处理了 Git 命令执行失败的情况 (`GitException`)。

2. **操作系统及平台信息获取**:
   - 提供了一系列判断当前操作系统类型的函数，例如 `is_linux`, `is_windows`, `is_osx`, `is_android` 等。
   - 提供了获取 Windows 本地架构的函数 (`windows_detect_native_arch`)。
   - 提供了获取 macOS 目标文件架构的函数 (`darwin_get_object_archs`)。

3. **文件及路径操作**:
   - 定义了 `File` 类来表示源文件或构建生成的文件，包含了判断文件是否已构建、获取相对路径和绝对路径等方法。
   - 定义了 `FileMode` 类来处理文件权限，可以将符号表示的权限字符串转换为数字表示。
   - 提供了创建临时目录的类 (`TemporaryDirectoryWinProof`)，并处理了 Windows 下删除文件和目录的特殊情况 (`windows_proof_rm`, `windows_proof_rmtree`)。
   - 提供了判断路径是否在根目录下的函数 (`path_is_in_root`)。
   - 提供了创建相对路径的函数 (`relative_to_if_possible`, `relpath`)。

4. **进程执行**:
   - 提供了安全执行子进程的函数 (`Popen_safe`, `Popen_safe_logged`)，并处理了可能出现的异常。

5. **字符串及列表操作**:
   - 提供了将参数列表组合成字符串的函数 (`join_args`)，以及将字符串拆分成参数列表的函数 (`split_args`, `shlex.split`)。
   - 提供了将值转换为列表的函数 (`listify`, `listify_array_value`, `stringlistify`, `typeslistify`)。
   - 提供了替换字符串中占位符的函数 (`substitute_values`, `do_replacement`)。
   - 提供了判断子字符串是否在列表中的函数 (`substring_is_in_list`)。
   - 提供了转义参数以便在 shell 中安全使用的函数 (`quote_arg`)。

6. **版本比较**:
   - 定义了 `Version` 类用于表示和比较软件版本号，支持各种比较运算符。
   - 提供了比较版本号的函数 (`version_compare`, `version_compare_many`, `version_compare_condition_with_min`)。
   - 提供了从字符串中搜索版本号的函数 (`search_version`)。

7. **编译器处理**:
   - 提供了根据源文件类型获取对应编译器的函数 (`get_compiler_for_source`)。
   - 提供了对统一编译源文件进行分类的函数 (`classify_unity_sources`)。

8. **配置处理**:
   - 提供了生成配置头文件的函数 (`dump_conf_header`, `do_conf_file`, `do_conf_str`)。
   - 提供了获取文件名模板字典的函数 (`get_filenames_templates_dict`)。
   - 提供了获取变量正则表达式的函数 (`get_variable_regex`)。

9. **数据结构**:
   - 定义了枚举类 `MachineChoice` 来表示构建机器和宿主机。
   - 定义了 `PerMachine` 和 `PerThreeMachine` 类来存储不同机器上的属性。
   - 定义了 `OrderedSet` 类来维护元素的插入顺序且不允许重复。

10. **异常处理**:
    - 定义了 `EnvironmentException` 和 `GitException` 用于表示特定类型的错误。

11. **其他工具函数**:
    - 提供了检查目录项问题的函数 (`check_direntry_issues`)。
    - 提供了展开参数的函数 (`expand_arguments`)。
    - 提供了获取第一个元素的函数 (`first`)。
    - 提供了生成列表的函数 (`generate_list`)。
    - 提供了获取 Wine 短路径的函数 (`get_wine_shortpath`)。
    - 提供了运行一次的装饰器 (`run_once`)。
    - 提供了检查可执行文件是否存在的函数 (`exe_exists`)。
    - 提供了 pickle 加载的函数 (`pickle_load`)。

**与逆向方法的关联及举例说明：**

`universal.py` 文件本身主要提供的是构建系统的通用工具，与直接的逆向方法关联较少。但其中某些功能在逆向工程的辅助环节可能会被间接使用。

* **操作系统及平台信息获取**:  在逆向分析时，了解目标程序的运行平台至关重要。例如，判断目标是运行在 Android 还是 Windows 上，可以帮助选择合适的逆向工具和技术。Frida 作为一款动态插桩工具，需要在目标平台上运行 Agent，这些平台判断函数可以帮助 Frida 确定运行环境。

* **进程执行**:  在逆向过程中，可能需要执行一些辅助工具或者脚本来辅助分析，例如执行反汇编器、调试器等。`Popen_safe` 等函数可以用来安全地执行这些外部命令。

* **文件及路径操作**:  逆向分析经常需要处理目标程序及其相关的各种文件，例如配置文件、库文件等。`File` 类和相关的路径操作函数可以方便地管理这些文件路径。

**涉及到二进制底层，Linux, Android 内核及框架的知识的举例说明：**

* **操作系统判断函数 (`is_linux`, `is_android` 等)**: 这些函数的实现依赖于对操作系统标识信息的读取，例如 `platform.system()` 的返回值，或者特定系统文件的存在性（例如 `/etc/debian_version`）。这涉及到操作系统底层的标识机制。

* **Windows 本地架构检测 (`windows_detect_native_arch`)**: 该函数使用了 Windows API `IsWow64Process2` 来检测进程和系统的架构。这直接与 Windows 内核提供的接口相关。

* **macOS 目标文件架构获取 (`darwin_get_object_archs`)**: 该函数使用了 `lipo` 命令，这是一个 macOS 提供的用于操作通用 (Universal) 格式库文件的工具。通用格式库文件包含了针对多种架构的二进制代码。这涉及到 macOS 底层的二进制文件格式知识。

**逻辑推理的假设输入与输出：**

假设输入一个文件路径字符串 `/path/to/my/source.c` 给 `File.from_source_file(source_root, subdir, fname)`：

* **假设输入**:
    * `source_root`: `/path/to/my`
    * `subdir`: `.`
    * `fname`: `source.c`
* **输出**:
    * 如果 `/path/to/my/source.c` 文件存在，则返回一个 `File` 对象，其 `is_built` 为 `False`， `subdir` 为 `.`， `fname` 为 `source.c`。
    * 如果 `/path/to/my/source.c` 文件不存在，则抛出 `MesonException`。

假设输入一个版本号字符串 `"1.2.3"` 和一个比较条件 `" >= 1.2.0"` 给 `version_compare`:

* **假设输入**:
    * `vstr1`: `"1.2.3"`
    * `vstr2`: `" >= 1.2.0"`
* **输出**: `True`，因为 1.2.3 大于等于 1.2.0。

**涉及用户或者编程常见的使用错误，请举例说明：**

* **文件权限设置错误**: 用户在使用 `FileMode` 类时，可能会提供格式错误的权限字符串，例如 `"rwxr-xr"` (少一位)，或者包含无效字符。 这会导致 `FileMode.perms_s_to_bits` 函数抛出 `MesonException`。

* **版本号比较字符串错误**:  用户在调用 `version_compare` 时，可能会提供格式错误的比较条件字符串，例如 `" > = 1.0"` (空格错误)。虽然代码会尝试解析，但复杂的错误可能会导致意外的结果。

* **子进程执行参数错误**: 用户在使用 `Popen_safe` 等函数执行子进程时，提供的参数列表可能不正确，例如缺少必要的参数或者参数顺序错误，这会导致子进程执行失败。

**说明用户操作是如何一步步的到达这里，作为调试线索。**

1. **用户执行 `meson` 命令**: 用户在项目根目录下执行 `meson` 命令来配置构建系统。

2. **Meson 读取构建定义**: `meson` 命令会读取项目根目录下的 `meson.build` 文件，该文件定义了项目的构建规则。

3. **处理 Frida-CLR 子项目**:  在 `meson.build` 文件中，Frida-CLR 被定义为一个子项目。Meson 会递归地处理该子项目的 `meson.build` 文件。

4. **执行 Frida-CLR 的构建逻辑**: 在 Frida-CLR 的 `meson.build` 文件中，可能需要执行一些通用的构建任务，例如查找 Git 版本、判断操作系统类型、处理文件路径等。

5. **调用 `universal.py` 中的函数**:  在执行这些构建任务的过程中，Meson 的内部模块可能会调用 `frida/subprojects/frida-clr/releng/meson/mesonbuild/utils/universal.py` 文件中定义的通用工具函数。例如，当需要获取当前 Git 版本时，可能会调用 `git` 函数；当需要判断当前操作系统是否为 Windows 时，可能会调用 `is_windows` 函数。

6. **调试线索**: 如果用户在配置或构建 Frida-CLR 时遇到问题，例如由于 Git 未安装导致构建失败，或者由于平台判断错误导致编译选项不正确，那么调试信息可能会指向 `universal.py` 文件中的相关函数。例如，如果 `git` 函数抛出 `GitException`，则说明 Git 命令执行失败；如果平台判断函数返回了错误的结果，则可能导致后续的构建逻辑出错。

总而言之，`universal.py` 提供了一系列基础且常用的功能，这些功能被 `Meson` 构建系统的其他模块广泛使用，以完成各种构建任务。理解这个文件的功能有助于理解 `Meson` 构建系统的内部运作机制。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/utils/universal.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
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
"""


```