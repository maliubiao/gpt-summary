Response:
The user wants me to analyze a Python source code file related to the Frida dynamic instrumentation tool. I need to identify its functionalities and provide explanations, examples, and connections to various concepts like reverse engineering, binary/OS internals, logical reasoning, common user errors, and debugging.

Here's a breakdown of how to approach this:

1. **Understand the Context:** The file is located within the Frida project, specifically in `frida/subprojects/frida-node/releng/meson/mesonbuild/utils/`. This suggests it's a utility module used by the Meson build system for Frida's Node.js bindings release engineering.

2. **Identify Key Functionalities:** I'll go through the code, line by line, and categorize the functions, classes, and variables based on their purpose. This will involve:
    - Handling file paths and operations (e.g., `File` class, `replace_if_different`).
    - Executing external commands (e.g., `git`, `Popen_safe`).
    - Managing versions and comparisons (e.g., `Version` class, `version_compare`).
    - Detecting operating systems and architectures (e.g., `is_linux`, `windows_detect_native_arch`).
    - Handling configuration data (e.g., `dump_conf_header`).
    - Utility functions for lists and strings (e.g., `listify`, `stringlistify`).
    - Enums for machine types (e.g., `MachineChoice`).

3. **Relate to Reverse Engineering:** Think about how these functionalities could be relevant during reverse engineering. For example:
    - Executing commands like `git` can be used to retrieve source code versions or examine changes.
    - Version comparison is crucial when checking for vulnerabilities or compatible Frida versions.
    - OS and architecture detection is essential for targeting specific environments during instrumentation.

4. **Connect to Binary/OS Internals:**  Identify functions that interact with the underlying system:
    - `FileMode` relates to file permissions, a fundamental OS concept.
    - `windows_detect_native_arch` directly interacts with Windows API to get architecture information.

5. **Analyze Logical Reasoning:** Look for functions that perform comparisons or decisions based on input. The `version_compare` functions are prime examples here. I can create hypothetical version strings and show how the comparison logic works.

6. **Consider Common User Errors:** Think about how a user might misuse these utilities or encounter errors:
    - Providing incorrect file paths to functions like `File.from_source_file`.
    - Expecting version comparisons to work in a certain way without fully understanding the logic.
    - Having issues with Git commands if Git is not installed or configured correctly.

7. **Trace User Operations:**  Imagine a developer working on Frida's Node.js bindings and needing to use these utilities. How would they end up calling these functions? This might involve:
    - The Meson build system automatically invoking these utilities during the build process.
    - A developer writing custom build scripts that use these helper functions.

8. **Summarize Functionality (for Part 1):** Based on the analysis, I'll create a concise summary of the module's purpose and the types of tasks it performs.

**Mental Sandbox Simulation:**

I can imagine a scenario where Meson uses this module during the build process. For example, when building Frida for a specific platform, the `is_linux()` or `is_windows()` functions would be used to apply platform-specific build steps. The `git()` function might be used to fetch the Frida version from the Git repository. The `Version` class and related functions would be used to compare the required Meson version or dependencies. If a user has an old version of Meson, the version comparison functions would detect this.

**Constraint Checklist & Confidence Score:**

1. List functionalities: Yes.
2. Relation to reverse engineering with examples: Yes.
3. Relation to binary/OS internals with examples: Yes.
4. Logical reasoning with input/output: Yes.
5. Common user errors with examples: Yes.
6. Explain user operation to reach here: Yes.
7. Summarize functionality: Yes.

Confidence Score: 5/5 - I am confident I can address all the requirements.

Strategizing complete. I will now proceed with generating the response.
好的，让我们来详细分析一下 `frida/subprojects/frida-node/releng/meson/mesonbuild/utils/universal.py` 这个文件中的功能。

**核心功能归纳：**

这个 Python 文件 `universal.py` 是 Frida 项目中，用于构建 Node.js 绑定的 Meson 构建系统的一部分。它提供了一系列通用的辅助函数和类，用于处理各种构建相关的任务。其主要功能可以归纳为以下几点：

1. **系统和环境信息获取:**
   - 提供多种函数来检测当前操作系统类型 (如 `is_linux`, `is_windows`, `is_osx` 等)。
   - 提供函数来检测 Windows 的本地架构 (`windows_detect_native_arch`).
   - 提供函数来获取 Python 解释器的命令 (`python_command`).
   - 提供函数来获取 Meson 命令 (`get_meson_command`, `set_meson_command`).

2. **版本控制系统 (VCS) 集成:**
   - 提供函数 `detect_vcs` 来自动检测项目是否使用了 Git、Mercurial、Subversion 或 Bazaar，并获取 VCS 相关信息。
   - 封装了执行 Git 命令的函数 (`git`, `quiet_git`, `verbose_git`)，方便在构建过程中与 Git 仓库交互。

3. **版本比较和处理:**
   - 提供了 `Version` 类用于比较版本号，支持类似 RPM 的版本比较逻辑。
   - 提供了一系列版本比较函数 (`version_compare`, `version_compare_many`, `version_compare_condition_with_min`)，用于判断版本是否符合特定条件。
   - 提供了 `search_version` 函数，用于从字符串中提取版本号。

4. **文件和路径操作:**
   - 提供了 `File` 类来表示项目中的文件，区分构建生成的文件和源代码文件，并提供获取相对路径、绝对路径等方法.
   - 提供了 `FileMode` 类来处理文件权限设置。
   - 提供 `replace_if_different` 函数，用于在内容发生变化时才替换文件。
   - 提供 `relpath` 函数计算相对路径。
   - 提供 `path_is_in_root` 函数判断路径是否在根目录下。
   - 提供了处理临时目录和文件的类 (`TemporaryDirectoryWinProof`, `NamedTemporaryFile`).

5. **进程和命令执行:**
   - 提供了 `Popen_safe` 和 `Popen_safe_logged` 函数，用于安全地执行外部命令并捕获输出。

6. **配置数据处理:**
   - 提供了 `do_conf_file` 和 `do_conf_str` 函数，用于处理配置文件。
   - 提供了 `dump_conf_header` 函数，用于生成配置文件的头部信息。
   - 提供了 `do_replacement` 函数，用于进行字符串替换。

7. **数据结构和类型处理:**
   - 提供了 `OrderedSet` 类，用于维护元素顺序的集合。
   - 提供了 `PerMachine`, `PerThreeMachine` 等类，用于区分构建机器、宿主机和目标机器的配置。
   - 提供 `listify`, `stringlistify`, `typeslistify` 等函数，用于将不同类型的数据转换为列表。

8. **其他实用工具函数:**
   - 提供了 `run_once` 装饰器，用于确保函数只执行一次。
   - 提供了 `quote_arg` 函数，用于安全地引用命令行参数。
   - 提供了 `expand_arguments` 函数，用于展开参数列表。

**与逆向方法的关联及举例说明：**

虽然这个文件本身不是直接进行逆向操作的代码，但它提供的功能在逆向工程的上下文中非常有用：

* **版本信息获取和比较:** 在逆向分析一个二进制文件时，了解其构建所使用的库或工具的版本非常重要。`Version` 类和相关的比较函数可以用于：
    * **示例:** 假设你在分析一个使用了特定版本 OpenSSL 的程序，你可以编写一个脚本，使用 `search_version` 从程序的元数据中提取 OpenSSL 的版本号，然后使用 `version_compare` 函数来判断这个版本是否存在已知的漏洞。
* **操作系统和架构检测:** 逆向工程师经常需要针对不同的操作系统和架构进行分析。这个文件提供的操作系统和架构检测功能可以帮助自动化一些与平台相关的任务：
    * **示例:**  一个逆向工具可能需要根据目标程序的操作系统类型来选择不同的反汇编引擎或调试器。`is_windows()`, `is_linux()` 等函数可以用于动态加载相应的模块。
* **Git 集成:**  在分析开源软件或需要查看历史版本时，与 Git 仓库交互是常见的需求。`git()` 函数可以用于：
    * **示例:**  在分析一个开源库的特定漏洞时，可以使用 `git log` 命令来查看与该漏洞相关的提交历史，或者使用 `git checkout` 切换到特定的版本进行调试。
* **执行外部命令:** 逆向工程中经常需要调用各种外部工具，如 `objdump`, `readelf` 等。`Popen_safe` 函数可以安全地执行这些命令并获取输出：
    * **示例:**  可以使用 `Popen_safe` 调用 `objdump -d <binary>` 来反汇编一个二进制文件，然后解析其输出进行分析。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

这个文件虽然不是直接操作二进制或内核的代码，但它在构建 Frida 这个动态插桩工具的过程中扮演着重要角色，而 Frida 本身就 heavily 依赖于这些底层知识：

* **二进制底层:**  Frida 的核心功能是动态修改进程的内存和执行流程。构建过程中需要处理各种二进制文件（例如，需要插桩的目标进程的二进制文件，Frida 的 Agent 库等）。`File` 类用于管理这些文件，而 `darwin_get_object_archs` 函数用于获取 macOS 上二进制文件的架构信息，这直接关联到二进制文件的结构。
* **Linux 内核:** Frida 在 Linux 上依赖于诸如 `ptrace` 这样的内核机制来实现动态插桩。构建过程可能需要根据 Linux 发行版和内核版本进行一些调整。虽然这个文件本身不直接操作内核，但其提供的系统信息获取功能（例如，通过检测 `/etc/debian_version` 来判断是否是 Debian 系发行版）可以辅助进行这些调整。
* **Android 内核及框架:** Frida 也广泛应用于 Android 平台的逆向和安全分析。构建 Frida 的 Android 版本需要了解 Android 的架构和框架。虽然这个文件不直接处理 Android 特有的内核或框架细节，但其通用的构建辅助功能仍然适用，例如文件管理、命令执行等。

**逻辑推理及假设输入与输出:**

让我们以 `version_compare` 函数为例进行逻辑推理：

**假设输入:**

* `vstr1`: "1.2.3"
* `vstr2`: ">=1.2.0"

**逻辑推理:**

1. `_version_extract_cmpop(">=1.2.0")` 会提取出比较操作符 `operator.ge` 和版本字符串 "1.2.0"。
2. `Version("1.2.3")` 和 `Version("1.2.0")` 会被创建，分别将字符串解析成可比较的版本对象。
3. `operator.ge(Version("1.2.3"), Version("1.2.0"))` 会进行比较。版本 "1.2.3" 大于等于 "1.2.0"。

**预期输出:** `True`

**假设输入:**

* `vstr1`: "1.0"
* `vstr2`: "<1.0"

**逻辑推理:**

1. `_version_extract_cmpop("<1.0")` 会提取出比较操作符 `operator.lt` 和版本字符串 "1.0"。
2. `Version("1.0")` 和 `Version("1.0")` 会被创建。
3. `operator.lt(Version("1.0"), Version("1.0"))` 会进行比较。版本 "1.0" 不小于 "1.0"。

**预期输出:** `False`

**涉及用户或者编程常见的使用错误及举例说明:**

* **错误的路径:**  如果用户在调用 `File.from_source_file` 时提供了不存在的路径，会抛出 `MesonException`。
    * **示例:**  `File.from_source_file("/path/to/source", "subdir", "nonexistent_file.c")` 会因为找不到 `nonexistent_file.c` 而失败。
* **不正确的版本字符串格式:**  如果传递给 `Version` 类的字符串不是有效的版本号格式，可能会导致比较结果不符合预期。
    * **示例:**  `Version("invalid-version")` 可能会导致后续的版本比较出错。
* **Git 命令执行失败:** 如果用户环境中没有安装 Git 或者 Git 仓库存在问题，调用 `git()` 函数可能会抛出 `GitException`。
    * **示例:**  如果在没有 Git 的环境下调用 `git(["log"], ".")` 会失败。
* **权限问题:** 在使用 `FileMode` 设置文件权限时，如果用户没有足够的权限进行修改，可能会导致操作失败。

**用户操作是如何一步步的到达这里，作为调试线索：**

作为一个 Frida 的开发者或用户，你可能在以下场景中会间接地触发对这个文件的使用：

1. **构建 Frida 的 Node.js 绑定:** 当你使用 Meson 构建 Frida 的 Node.js 绑定时，Meson 会解析 `meson.build` 文件，其中可能包含调用这个文件中定义的函数的逻辑。例如，检查当前系统的类型，获取 Git 版本信息等。
2. **开发 Frida 的构建系统:** 如果你正在修改 Frida 的构建系统，你可能会直接使用或修改这个文件中的函数。
3. **调试构建问题:** 当构建过程中出现问题时，你可能需要查看 Meson 的日志输出，这些日志可能会包含这个文件中函数的执行信息，帮助你定位问题。例如，如果 Git 命令执行失败，日志中会显示相关的错误信息。
4. **编写自定义的构建脚本:**  开发者可能会编写自定义的脚本来自动化一些构建相关的任务，这些脚本可能会导入并使用 `universal.py` 中的函数。

**功能归纳（第 1 部分）：**

在第 1 部分中，`universal.py` 文件主要提供了以下功能：

* **系统和环境信息检测：**  用于获取操作系统类型、架构、Python 和 Meson 命令路径等信息，为后续的构建决策提供基础。
* **版本控制集成：**  方便地与 Git 等版本控制系统交互，获取版本信息，这对于维护和发布软件至关重要。
* **版本比较和处理：**  提供强大的版本比较能力，用于检查依赖项版本、判断功能支持情况等。
* **基本的文件和路径操作：**  提供文件对象的抽象和一些基础的文件系统操作，用于管理构建过程中的文件。

总而言之，`universal.py` 是一个为 Frida 的 Node.js 绑定构建过程提供通用工具函数的模块，它封装了常见的系统交互、版本管理和文件操作，简化了构建脚本的编写并提高了代码的可维护性。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/utils/universal.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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