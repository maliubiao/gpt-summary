Response:
The user wants a summary of the functionality of the Python code provided. I need to go through the code and identify the different types of operations and utilities it offers. I should pay special attention to parts related to reverse engineering, binary interaction, Linux/Android specifics, logical reasoning, potential user errors, and how a user might end up interacting with this code.

Here's a breakdown of the thinking process to achieve the desired summary:

1. **Understand the Context:** The code belongs to `frida-qml`, a component of the Frida dynamic instrumentation toolkit. This immediately suggests that many utilities will be related to interacting with processes, files, and potentially system-level details. The `releng/meson/mesonbuild/utils/universal.py` path hints at build system utilities, particularly for the Meson build system.

2. **High-Level Scoping:**  The initial imports provide a good overview of the general purpose of the file:
    * Basic utilities: `pathlib`, `argparse`, `enum`, `sys`, `stat`, `time`, `abc`, `platform`, `subprocess`, `operator`, `os`, `shlex`, `shutil`, `re`, `collections`, `functools`, `itertools`, `tempfile`, `typing`, `textwrap`, `pickle`, `errno`, `json`.
    * Meson-specific elements: `mesonbuild.mlog`, `.core`, `.._typing`, `..build`, `..coredata`, `..environment`, `..compilers.compilers`, `..interpreterbase.baseobjects`.

3. **Categorize Functionality by Area:**  Scan through the code and group functions and classes based on their apparent purpose. Some key categories emerge:

    * **Git Interaction:** Functions like `git`, `quiet_git`, `verbose_git`, `detect_vcs`.
    * **Path/File Handling:** Classes like `File`, `FileMode`, and functions like `relpath`, `replace_if_different`, `windows_proof_rm`, `windows_proof_rmtree`.
    * **Version Comparison:** The `Version` class and functions like `version_compare`, `version_compare_many`, `version_compare_condition_with_min`.
    * **System Information:** Functions checking the operating system (`is_linux`, `is_windows`, etc.), architecture (`windows_detect_native_arch`), and environment.
    * **Process Execution:** `Popen_safe`, `Popen_safe_logged`, `exe_exists`.
    * **Build System Helpers:** Functions related to configuration (`dump_conf_header`, `do_conf_file`, `do_conf_str`), command handling (`get_meson_command`, `set_meson_command`), and potentially compiler selection (`get_compiler_for_source`, `classify_unity_sources`).
    * **Data Structures:**  `OrderedSet`, `PerMachine`, `PerThreeMachine`.
    * **String/List Manipulation:**  Functions like `listify`, `stringlistify`, `split_args`.

4. **Address Specific Requirements from the Prompt:**

    * **Reverse Engineering:** Look for functions that might be useful in the context of Frida. While this file is more about build utilities, functions related to process execution (`Popen_safe`), file manipulation, and potentially even version detection could indirectly play a role.
    * **Binary/Low-Level:** Functions interacting with the operating system (like checking OS type or architecture) and those related to process execution or file permissions (`FileMode`) fall into this category.
    * **Linux/Android Kernel/Framework:**  The OS checks (`is_linux`, `is_android`) and functions that might be used to determine system capabilities indirectly relate to this.
    * **Logical Reasoning:**  The version comparison functions involve logical comparisons. The `PerMachine` and `PerThreeMachine` classes involve a degree of abstraction and conditional logic.
    * **User Errors:** Consider scenarios where users might misuse the provided utilities. For example, providing an incorrect file path to `File.from_source_file` or using incorrect version strings with the comparison functions.
    * **User Operation Flow:**  Imagine the steps a developer might take when using Frida and how they might indirectly trigger the use of this utility file during the build process.

5. **Synthesize the Summary:** Combine the categorized functionalities and the specific requirements into a concise summary. Highlight the main areas of functionality.

6. **Review and Refine:** Ensure the summary accurately reflects the code's purpose and addresses all aspects of the prompt. For example, initially, I might focus too much on the build system aspects and not enough on the potential indirect connections to reverse engineering. Reviewing helps to balance this. Also, making sure to use clear and understandable language. For example, instead of just saying "OS checks," explain *why* these checks might be relevant (e.g., for platform-specific builds).

By following these steps, I can arrive at a comprehensive and accurate summary of the provided Python code. The categorization helps to structure the information, and addressing the specific requirements ensures all aspects of the prompt are covered.
这是 `frida/subprojects/frida-qml/releng/meson/mesonbuild/utils/universal.py` 文件的源代码，它是一个 Frida 动态 instrumentation 工具项目的一部分，并且使用了 Meson 构建系统。这个文件包含了各种通用的辅助功能。

**功能归纳:**

这个 Python 文件提供了一系列通用的实用工具函数和类，主要用于：

1. **操作系统和环境信息获取:**
   - 检测当前操作系统类型 (Linux, Windows, macOS, Android 等)。
   - 检测是否在 WSL 或 Cygwin 环境中运行。
   - 获取 Python 解释器命令。
   - 检测 Windows 的原生架构 (x86, amd64, arm64)。

2. **版本控制系统 (VCS) 支持:**
   - 检测当前项目是否使用 Git, Mercurial, Subversion 或 Bazaar。
   - 执行 Git 命令并处理输出。

3. **文件和路径操作:**
   - 表示文件 (`File` 类)，包括构建的文件和源文件。
   - 处理文件权限 (`FileMode` 类)。
   - 创建临时的目录和文件。
   - 安全地删除文件和目录 (针对 Windows 做了特殊处理)。
   - 检查路径是否存在于根目录下。
   - 获取相对路径。

4. **字符串和列表操作:**
   - 将值转换为列表。
   - 将列表中的元素转换为字符串。
   - 字符串替换。
   - 分割和连接命令行参数。
   - 检查字符串是否为 ASCII。

5. **版本比较:**
   - 提供 `Version` 类用于复杂的版本号比较 (类似于 RPM 的版本比较逻辑)。
   - 提供函数进行版本比较 (`version_compare`, `version_compare_many`, `version_compare_condition_with_min`)。

6. **进程执行:**
   - 安全地执行子进程 (`Popen_safe`, `Popen_safe_logged`)。
   - 检查可执行文件是否存在。

7. **构建系统相关:**
   - 处理配置文件的生成 (`dump_conf_header`, `do_conf_file`, `do_conf_str`)。
   - 管理 Meson 命令的获取和设置。
   - 辅助确定用于编译特定源代码文件的编译器 (`get_compiler_for_source`, `classify_unity_sources`)。
   - 处理项目 Meson 版本信息。

8. **数据结构和类型:**
   - 定义了枚举类型 `MachineChoice` 表示构建和主机。
   - 定义了泛型类 `PerMachine` 和 `PerThreeMachine` 用于表示不同机器上的值。
   - 定义了 `OrderedSet` (尽管代码片段中没有直接展示其实现，但被导入了)。

**与逆向方法的关系及举例说明:**

虽然这个文件本身主要是构建辅助工具，但它的一些功能间接地与逆向方法有关：

* **进程执行 (`Popen_safe`, `Popen_safe_logged`):** 在逆向工程中，可能需要执行一些外部工具来分析或操作目标程序。例如，可以使用 `Popen_safe` 来运行 `objdump` 或 `readelf` 等工具来分析二进制文件。

   **举例:** 假设在逆向 Android 的某个 native library 时，需要使用 `adb shell` 执行一些命令。Frida 可能会使用 `Popen_safe` 来执行类似 `adb shell getprop ro.product.cpu.abi` 的命令来获取设备的架构信息，这对于后续的 instrumentation 策略至关重要。

* **文件操作 (`File`, `FileMode`, `replace_if_different`):**  逆向过程中可能需要处理目标程序的二进制文件、配置文件等。这些工具可以用来读取、修改或替换这些文件。

   **举例:** 在对一个 Linux 应用程序进行 hook 时，可能需要修改其配置文件以启用某些调试选项。Frida 可以使用这里的文件操作工具来修改目标应用程序的配置文件。

* **操作系统和环境信息获取:**  了解目标程序的运行环境是逆向分析的基础。例如，知道目标程序运行在 Android 上还是 Linux 上，其 CPU 架构是什么，可以帮助选择合适的 hook 技术和工具。

   **举例:**  Frida 需要知道目标 Android 设备的架构 (arm, arm64, x86) 才能加载对应架构的 Agent 代码。`is_android()` 和 `windows_detect_native_arch()` 等函数提供的功能就直接服务于这个目的。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **操作系统类型检测 (`is_linux`, `is_android`, etc.):** 这些函数直接关联到操作系统内核提供的接口和信息，是与底层交互的基础。

   **举例:** Frida 需要根据目标设备的操作系统类型来加载不同的运行时组件和使用不同的 API 进行进程注入和 hook 操作。

* **进程执行 (`Popen_safe`):**  执行外部命令涉及到操作系统提供的进程管理接口，例如 `fork`, `execve` (Linux) 或 `CreateProcess` (Windows)。

   **举例:**  Frida 使用 `Popen_safe` 运行 `frida-server` 或与 `frida-server` 通信时，就涉及到与操作系统进程管理相关的知识。

* **Windows 架构检测 (`windows_detect_native_arch`):**  这个函数使用了 Windows 特有的 API (`IsWow64Process2`) 来判断系统的原生架构，这涉及到对 Windows 内核和底层架构的理解。

   **举例:** 在 Windows 上，一个 32 位的进程可以运行在 64 位的系统上，但 Frida 需要知道系统的原生架构来正确加载 Agent。

* **文件权限 (`FileMode`):** 文件权限是操作系统安全模型的重要组成部分，`FileMode` 类操作的实际上是操作系统提供的文件权限管理机制。

   **举例:** 在某些逆向场景下，可能需要修改目标文件的执行权限以便进行调试或注入。

**逻辑推理 (假设输入与输出):**

* **`version_compare("1.2.3", ">=1.2.0")`:**
    * **假设输入:**  版本字符串 "1.2.3" 和比较条件 ">=1.2.0"。
    * **输出:** `True` (因为 1.2.3 大于等于 1.2.0)。

* **`is_linux()` 在 Linux 系统上运行:**
    * **假设输入:**  代码在 Linux 操作系统上执行。
    * **输出:** `True`。

* **`detect_vcs("/path/to/git/repo")`:**
    * **假设输入:**  `/path/to/git/repo` 是一个有效的 Git 仓库目录。
    * **输出:**  一个包含 Git 相关信息的字典，例如 `{'name': 'git', 'cmd': 'git', 'repo_dir': '.git', ...}`。

**用户或编程常见的使用错误及举例说明:**

* **在期望文件路径时传递了错误的字符串:**  例如，在使用 `File.from_source_file` 时，如果传递的 `subdir` 和 `fname` 组合起来不是一个实际存在的文件，则会抛出 `MesonException`。

   **举例:** `File.from_source_file("/my/project", "src", "nonexistent.c")` 会抛出异常，因为 `nonexistent.c` 不存在。

* **使用不支持的 VCS 命令:** 如果项目使用了不支持的 VCS，`detect_vcs` 将返回 `None`，如果代码没有妥善处理这种情况，可能会导致后续的空指针或属性访问错误。

   **举例:** 如果项目使用 Plastic SCM，但 `detect_vcs` 中没有对应的支持，它会返回 `None`。如果代码直接访问返回值的 `name` 属性，例如 `vcs_info['name']`，则会抛出 `TypeError`。

* **在 Windows 上进行文件操作时没有考虑路径分隔符:** 虽然 `os.path.join` 已经做了处理，但如果用户手动拼接路径，可能会在 Windows 上使用 `/` 作为分隔符，导致错误。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户想要构建一个使用了 Frida 的 QML 应用程序。**
2. **用户在项目根目录下运行 Meson 构建命令 (`meson setup build`).**
3. **Meson 构建系统开始解析 `meson.build` 文件和相关的构建配置。**
4. **在处理构建配置的过程中，Meson 可能会调用 Frida QML 子项目相关的构建脚本。**
5. **Frida QML 的构建脚本中可能需要执行一些通用的操作，例如检查操作系统类型、查找 Git 仓库、生成配置文件等。**
6. **为了实现这些通用操作，构建脚本会导入并使用 `frida/subprojects/frida-qml/releng/meson/mesonbuild/utils/universal.py` 文件中定义的函数和类。**

例如，在配置构建环境时，Meson 可能会使用 `is_linux()` 或 `is_windows()` 来确定需要使用哪些平台特定的编译选项。或者，在生成包含版本信息的头文件时，可能会调用 `detect_vcs()` 来获取当前 Git 仓库的版本号，并使用 `dump_conf_header()` 或 `do_conf_str()` 将其写入配置文件。

因此，这个 `universal.py` 文件作为 Frida QML 构建过程中的一个通用工具库，在 Meson 构建系统的驱动下被间接地调用和使用。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/utils/universal.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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