Response:
My thinking process to analyze the provided Python code and answer the user's request involved several steps:

1. **Understanding the Core Purpose:** I first read the docstring and the class names (like `ExternalProgram`, `NonExistingExternalProgram`, `OverrideProgram`) to grasp the primary function of the code. It's clearly about representing and locating external programs needed for a build system (likely Meson, based on the imports and copyright).

2. **Decomposition and Functional Analysis:** I then went through each class and significant function, noting their roles:
    * **`ExternalProgram`:**  The central class. It's responsible for finding, storing information about, and executing external programs. Key functionalities include searching for programs in PATH and specified directories, handling shebangs in scripts, and retrieving program versions.
    * **`NonExistingExternalProgram`:** A placeholder for when a program isn't found.
    * **`OverrideProgram`:**  Represents a program that overrides a default one.
    * **`find_external_program`:**  A helper function to locate external programs, considering cross-compilation settings.

3. **Identifying Connections to Reverse Engineering:** I looked for aspects of the code that could relate to reverse engineering. The most obvious link is the ability to *execute* external programs. In reverse engineering, tools like debuggers, disassemblers, and analysis scripts are often external programs. The code's handling of shebangs is also relevant, as many scripting tools used in reverse engineering start with a shebang.

4. **Pinpointing Binary/Kernel/Framework Interactions:** I searched for terms or functionalities that hinted at lower-level interactions:
    * **`os.stat`, `stat` module:** Indicate interaction with the file system, relevant to executable permissions and file types.
    * **`shutil.which`:**  A standard way to find executables, reflecting OS-level search mechanisms.
    * **Windows-specific handling (`windows_exts`, `_windows_sanitize_path`, `_search_windows_special_cases`):** Shows awareness of OS differences in executable handling.
    * **Shebang parsing:**  While not strictly kernel-level, understanding how scripts are invoked is crucial in many system-level scenarios, including those encountered during reverse engineering.
    * **Cross-compilation considerations:**  The `for_machine` parameter and the logic in `find_external_program` touch on the concept of targeting different architectures, which is highly relevant in reverse engineering embedded systems or analyzing software for different platforms.

5. **Looking for Logic and Reasoning:** I examined the code flow, particularly in the `_search` and `find_external_program` functions, to understand how decisions are made about locating programs. The logic for handling Windows PATH and extensions stood out as a case of specific reasoning.

6. **Spotting Potential User Errors:** I considered how a user might misuse or encounter issues with this code:
    * **Incorrect `command` specification:** Providing a non-existent path or the wrong command-line arguments.
    * **Missing dependencies:**  If an external program relied upon by the build process isn't installed or in the PATH.
    * **Cross-compilation misconfiguration:** Errors in the cross-compilation definition could lead to the wrong programs being selected.

7. **Tracing User Operations (Debugging Clues):** I imagined the user's steps leading to this code being executed. A build system like Meson takes user-defined build configurations (including specifying external programs) and uses this code to find those programs. Errors during this phase would likely surface within this module.

8. **Structuring the Answer:** Finally, I organized my findings into the requested categories: Functionality, Relation to Reverse Engineering, Binary/Kernel/Framework aspects, Logical Reasoning, User Errors, and Debugging Clues. I tried to provide concrete examples for each point to make the explanation clearer.

**Self-Correction/Refinement during the Process:**

* Initially, I might have focused too narrowly on the "reverse engineering" aspect. I realized the code's primary role is in a *build system*, and reverse engineering is just one area where external programs are used. I broadened my perspective accordingly.
* I double-checked my understanding of shebangs and how they work on different operating systems.
* I ensured my examples were specific and tied directly to the code's functionality. For instance, when discussing user errors, I didn't just say "path issues," but provided concrete examples like "incorrectly specified path."

By following these steps, I could create a comprehensive and accurate answer to the user's detailed request.
这是 `frida/releng/meson/mesonbuild/programs.py` 文件的源代码，它属于 Frida 这个动态 instrumentation 工具的构建系统 Meson 的一部分。这个文件的主要作用是**管理和查找在构建过程中需要用到的外部程序**。

下面分别列举其功能，并根据要求进行说明：

**功能列举：**

1. **表示外部程序 (`ExternalProgram` 类):**
   - 存储外部程序的名字 (`name`)。
   - 存储外部程序的完整命令，包括路径和参数 (`command`)。
   - 记录外部程序的路径 (`path`)。
   - 缓存外部程序的版本信息 (`cached_version`)，避免重复获取。
   - 提供方法来判断程序是否找到 (`found()`)。
   - 提供获取程序命令 (`get_command()`) 和路径 (`get_path()`) 的方法。
   - 提供获取程序版本 (`get_version()`) 的方法，通过执行 `--version` 命令并解析输出。
   - 提供人可读的命令描述 (`description()`)。
   - 提供用于构建概要信息的字符串值 (`summary_value()`).

2. **查找外部程序:**
   - 构造函数 `__init__` 可以通过程序名在系统的 PATH 环境变量中搜索程序。
   - 可以指定额外的搜索目录 (`search_dir`, `extra_search_dirs`) 来查找程序。
   - 针对 Windows 系统有特殊的处理逻辑，比如搜索带有 `.exe`, `.com` 等扩展名的文件 (`windows_exts`)，处理没有扩展名的可执行文件，以及处理 shebang。
   - 使用 `shutil.which` 在 PATH 中查找程序。
   - 提供静态方法 `from_bin_list` 从构建环境配置中查找特定机器 (`for_machine`) 的二进制程序。
   - 提供静态方法 `from_entry` 从已知的命令字符串或列表创建 `ExternalProgram` 对象。

3. **处理 Shebang (`_shebang_to_cmd`):**
   - 可以解析脚本文件的 Shebang 行（例如 `#!/usr/bin/python3`），确定执行该脚本所需的解释器。
   - 在 Windows 和 Haiku 系统上，对 Shebang 的处理有特殊的逻辑，例如将 `/usr/bin/env python3` 转换为实际的 Python 命令。

4. **判断是否为可执行文件 (`_is_executable`):**
   - 根据文件扩展名（Windows）或文件权限（其他系统）判断文件是否可执行。

5. **处理找不到的外部程序 (`NonExistingExternalProgram` 类):**
   - 提供一个特殊的 `ExternalProgram` 子类，表示程序未找到。

6. **表示覆盖的程序 (`OverrideProgram` 类):**
   - 提供一个 `ExternalProgram` 子类，用于表示用户覆盖了默认的程序。

7. **查找外部程序的辅助函数 (`find_external_program`):**
   - 接收程序名、显示名、默认名称列表以及是否允许交叉编译的默认值等参数。
   - 首先在构建环境配置中查找指定名称的程序。
   - 如果找不到，则尝试使用默认名称列表中的程序。
   - 考虑交叉编译的情况，如果目标平台不允许使用默认程序，则不会尝试默认值。

**与逆向方法的关联及举例说明：**

Frida 本身就是一个动态 instrumentation 工具，主要用于逆向工程、安全研究和动态分析。这个 `programs.py` 文件虽然不直接执行逆向操作，但它负责管理 Frida 构建过程中需要的工具，这些工具可能与逆向方法有关。

**举例说明：**

假设 Frida 的构建过程需要用到 `make` 工具。`programs.py` 会查找系统中的 `make` 程序。逆向工程师在构建 Frida 时，实际上是在构建一个用于动态分析的工具。`make` 工具的成功找到并执行是 Frida 构建过程的一部分。

更具体的例子，如果 Frida 需要编译一些 C 代码来生成 agent，那么构建过程可能会用到 `gcc` 或 `clang`。`programs.py` 就负责查找这些编译器。编译器是逆向工程中静态分析的基础，编译出的二进制文件就是逆向分析的对象。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

这个文件本身的代码更多关注于文件系统和进程执行，与二进制底层、内核等知识的关联比较间接，主要体现在它管理的程序上。

**举例说明：**

1. **二进制底层：** 当 `programs.py` 找到 `gcc` 并执行它来编译 Frida 的 C 代码时，`gcc` 的工作是将高级语言代码转换为机器码（二进制）。这个过程深入到了二进制表示、指令集架构等底层知识。

2. **Linux：**
   - 文件权限：`_is_executable` 方法通过检查文件的执行权限位来判断是否可执行，这是 Linux 文件系统的基本概念。
   - PATH 环境变量：程序的搜索依赖于 PATH 环境变量，这是 Linux 和其他 Unix-like 系统中查找可执行文件的标准方式。
   - Shebang：`_shebang_to_cmd` 方法解析 Shebang 行，这是 Linux 系统中执行脚本的常用机制。

3. **Android 内核及框架：**
   - 虽然这个文件本身不直接涉及 Android 内核，但 Frida 的目标之一就是在 Android 平台上进行动态 instrumentation。构建 Frida 的过程可能需要用到 Android SDK 中的工具，例如 `adb`（Android Debug Bridge）。`programs.py` 可能会查找 `adb` 程序。
   - Frida Agent 的编译可能需要针对 Android 平台特定的库和头文件，这会涉及到 Android 框架的知识。

**逻辑推理及假设输入与输出：**

**假设输入：**

- 用户在构建 Frida 时，Meson 需要查找 `python3` 解释器。
- `name` 参数为 `"python3"`。
- 用户的 PATH 环境变量中包含 `/usr/bin`，且 `/usr/bin/python3` 是一个可执行文件。

**逻辑推理：**

- `ExternalProgram` 的 `__init__` 方法被调用，`name` 为 `"python3"`。
- 由于没有提供 `command`，代码会尝试在 PATH 中搜索 `"python3"`。
- `_search` 方法会被调用，最终调用 `shutil.which("python3")`。
- `shutil.which` 会在 PATH 环境变量中查找 `"python3"`，找到 `/usr/bin/python3`。

**输出：**

- `ExternalProgram` 对象的 `found()` 方法返回 `True`。
- `ExternalProgram` 对象的 `command` 属性为 `['/usr/bin/python3']`。
- `ExternalProgram` 对象的 `path` 属性为 `'/usr/bin/python3'`。

**涉及用户或编程常见的使用错误及举例说明：**

1. **PATH 环境变量未配置：** 如果用户没有将所需的外部程序所在的目录添加到 PATH 环境变量中，`programs.py` 可能无法找到该程序。
   - **错误示例：** 构建 Frida 需要 `cmake`，但 `cmake` 的安装目录 `/opt/cmake/bin` 没有添加到 PATH 中。Meson 会报告找不到 `cmake`。

2. **程序名拼写错误：** 用户或构建脚本中指定的程序名与实际的程序名不符。
   - **错误示例：** 构建脚本中指定需要 `"pyhton3"`（拼写错误）而不是 `"python3"`，导致查找失败。

3. **缺少依赖：** 某些外部程序可能依赖于其他的库或程序。即使 `programs.py` 找到了该程序，但如果其依赖缺失，运行时可能会出错。
   - **错误示例：** 某个构建工具依赖于特定的 C++ 库，如果该库未安装，即使找到了该工具，构建过程也会失败。

4. **权限问题：** 找到的程序可能没有执行权限。
   - **错误示例：** 在某些情况下，用户可能下载了一个可执行文件，但忘记赋予其执行权限 (`chmod +x`)，导致 `programs.py` 找到该文件但无法执行。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

当用户执行 Frida 的构建命令（通常是 `meson build` 或 `ninja`），构建系统 Meson 会按照 `meson.build` 文件中的指示进行构建。

1. **配置阶段：** 用户运行 `meson build` 命令，Meson 会读取 `meson.build` 文件，这个文件中会声明构建目标、依赖项以及需要的外部程序。
2. **查找外部程序：** 当 Meson 解析到需要外部程序的指令时，例如 `find_program('gcc')`，就会调用 `frida/releng/meson/mesonbuild/programs.py` 中的相关函数来查找 `gcc`。
3. **`find_external_program` 调用：**  `mesonbuild/programs.py` 中的 `find_external_program` 函数会被调用，传入程序名（例如 `"gcc"`）和其他参数。
4. **搜索过程：** `find_external_program` 函数会尝试从构建配置、环境变量和默认路径中搜索程序。这会涉及到 `ExternalProgram` 类的实例化和其 `__init__` 方法中的搜索逻辑。
5. **结果反馈：** 如果找到程序，`ExternalProgram` 对象会记录其路径和命令。如果找不到，会创建一个 `NonExistingExternalProgram` 对象。
6. **构建执行：** 在后续的构建阶段（例如使用 `ninja`），Meson 会使用找到的外部程序来执行编译、链接等操作。

**作为调试线索：**

- **构建失败信息：** 如果构建失败，错误信息可能会指示找不到某个程序。这可以作为调试的起点。
- **Meson 日志：** Meson 会生成详细的日志，其中会记录查找外部程序的过程和结果。查看日志可以了解哪些程序被成功找到，哪些没有找到，以及搜索的路径。
- **环境变量检查：** 如果怀疑是 PATH 环境变量的问题，可以检查当前的 PATH 设置。
- **构建文件检查：** 检查 `meson.build` 文件中指定的程序名是否正确。

总而言之，`frida/releng/meson/mesonbuild/programs.py` 文件是 Frida 构建系统的重要组成部分，它负责管理和查找构建过程中需要的各种外部工具，为后续的编译、链接等操作奠定基础。理解这个文件的功能有助于理解 Frida 的构建过程，并在构建遇到问题时提供调试线索。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/programs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2013-2020 The Meson development team

from __future__ import annotations

"""Representations and logic for External and Internal Programs."""

import functools
import os
import shutil
import stat
import sys
import re
import typing as T
from pathlib import Path

from . import mesonlib
from . import mlog
from .mesonlib import MachineChoice, OrderedSet

if T.TYPE_CHECKING:
    from .environment import Environment
    from .interpreter import Interpreter


class ExternalProgram(mesonlib.HoldableObject):

    """A program that is found on the system."""

    windows_exts = ('exe', 'msc', 'com', 'bat', 'cmd')
    for_machine = MachineChoice.BUILD

    def __init__(self, name: str, command: T.Optional[T.List[str]] = None,
                 silent: bool = False, search_dir: T.Optional[str] = None,
                 extra_search_dirs: T.Optional[T.List[str]] = None):
        self.name = name
        self.path: T.Optional[str] = None
        self.cached_version: T.Optional[str] = None
        if command is not None:
            self.command = mesonlib.listify(command)
            if mesonlib.is_windows():
                cmd = self.command[0]
                args = self.command[1:]
                # Check whether the specified cmd is a path to a script, in
                # which case we need to insert the interpreter. If not, try to
                # use it as-is.
                ret = self._shebang_to_cmd(cmd)
                if ret:
                    self.command = ret + args
                else:
                    self.command = [cmd] + args
        else:
            all_search_dirs = [search_dir]
            if extra_search_dirs:
                all_search_dirs += extra_search_dirs
            for d in all_search_dirs:
                self.command = self._search(name, d)
                if self.found():
                    break

        if self.found():
            # Set path to be the last item that is actually a file (in order to
            # skip options in something like ['python', '-u', 'file.py']. If we
            # can't find any components, default to the last component of the path.
            for arg in reversed(self.command):
                if arg is not None and os.path.isfile(arg):
                    self.path = arg
                    break
            else:
                self.path = self.command[-1]

        if not silent:
            # ignore the warning because derived classes never call this __init__
            # method, and thus only the found() method of this class is ever executed
            if self.found():  # lgtm [py/init-calls-subclass]
                mlog.log('Program', mlog.bold(name), 'found:', mlog.green('YES'),
                         '(%s)' % ' '.join(self.command))
            else:
                mlog.log('Program', mlog.bold(name), 'found:', mlog.red('NO'))

    def summary_value(self) -> T.Union[str, mlog.AnsiDecorator]:
        if not self.found():
            return mlog.red('NO')
        return self.path

    def __repr__(self) -> str:
        r = '<{} {!r} -> {!r}>'
        return r.format(self.__class__.__name__, self.name, self.command)

    def description(self) -> str:
        '''Human friendly description of the command'''
        return ' '.join(self.command)

    def get_version(self, interpreter: T.Optional['Interpreter'] = None) -> str:
        if not self.cached_version:
            raw_cmd = self.get_command() + ['--version']
            if interpreter:
                res = interpreter.run_command_impl((self, ['--version']),
                                                   {'capture': True,
                                                    'check': True,
                                                    'env': mesonlib.EnvironmentVariables()},
                                                   True)
                o, e = res.stdout, res.stderr
            else:
                p, o, e = mesonlib.Popen_safe(raw_cmd)
                if p.returncode != 0:
                    cmd_str = mesonlib.join_args(raw_cmd)
                    raise mesonlib.MesonException(f'Command {cmd_str!r} failed with status {p.returncode}.')
            output = o.strip()
            if not output:
                output = e.strip()
            match = re.search(r'([0-9][0-9\.]+)', output)
            if not match:
                raise mesonlib.MesonException(f'Could not find a version number in output of {raw_cmd!r}')
            self.cached_version = match.group(1)
        return self.cached_version

    @classmethod
    def from_bin_list(cls, env: 'Environment', for_machine: MachineChoice, name: str) -> 'ExternalProgram':
        # There is a static `for_machine` for this class because the binary
        # always runs on the build platform. (It's host platform is our build
        # platform.) But some external programs have a target platform, so this
        # is what we are specifying here.
        command = env.lookup_binary_entry(for_machine, name)
        if command is None:
            return NonExistingExternalProgram()
        return cls.from_entry(name, command)

    @staticmethod
    @functools.lru_cache(maxsize=None)
    def _windows_sanitize_path(path: str) -> str:
        # Ensure that we use USERPROFILE even when inside MSYS, MSYS2, Cygwin, etc.
        if 'USERPROFILE' not in os.environ:
            return path
        # The WindowsApps directory is a bit of a problem. It contains
        # some zero-sized .exe files which have "reparse points", that
        # might either launch an installed application, or might open
        # a page in the Windows Store to download the application.
        #
        # To handle the case where the python interpreter we're
        # running on came from the Windows Store, if we see the
        # WindowsApps path in the search path, replace it with
        # dirname(sys.executable).
        appstore_dir = Path(os.environ['USERPROFILE']) / 'AppData' / 'Local' / 'Microsoft' / 'WindowsApps'
        paths = []
        for each in path.split(os.pathsep):
            if Path(each) != appstore_dir:
                paths.append(each)
            elif 'WindowsApps' in sys.executable:
                paths.append(os.path.dirname(sys.executable))
        return os.pathsep.join(paths)

    @staticmethod
    def from_entry(name: str, command: T.Union[str, T.List[str]]) -> 'ExternalProgram':
        if isinstance(command, list):
            if len(command) == 1:
                command = command[0]
        # We cannot do any searching if the command is a list, and we don't
        # need to search if the path is an absolute path.
        if isinstance(command, list) or os.path.isabs(command):
            if isinstance(command, str):
                command = [command]
            return ExternalProgram(name, command=command, silent=True)
        assert isinstance(command, str)
        # Search for the command using the specified string!
        return ExternalProgram(command, silent=True)

    @staticmethod
    def _shebang_to_cmd(script: str) -> T.Optional[T.List[str]]:
        """
        Check if the file has a shebang and manually parse it to figure out
        the interpreter to use. This is useful if the script is not executable
        or if we're on Windows (which does not understand shebangs).
        """
        try:
            with open(script, encoding='utf-8') as f:
                first_line = f.readline().strip()
            if first_line.startswith('#!'):
                # In a shebang, everything before the first space is assumed to
                # be the command to run and everything after the first space is
                # the single argument to pass to that command. So we must split
                # exactly once.
                commands = first_line[2:].split('#')[0].strip().split(maxsplit=1)
                if mesonlib.is_windows():
                    # Windows does not have UNIX paths so remove them,
                    # but don't remove Windows paths
                    if commands[0].startswith('/'):
                        commands[0] = commands[0].split('/')[-1]
                    if len(commands) > 0 and commands[0] == 'env':
                        commands = commands[1:]
                    # Windows does not ship python3.exe, but we know the path to it
                    if len(commands) > 0 and commands[0] == 'python3':
                        commands = mesonlib.python_command + commands[1:]
                elif mesonlib.is_haiku():
                    # Haiku does not have /usr, but a lot of scripts assume that
                    # /usr/bin/env always exists. Detect that case and run the
                    # script with the interpreter after it.
                    if commands[0] == '/usr/bin/env':
                        commands = commands[1:]
                    # We know what python3 is, we're running on it
                    if len(commands) > 0 and commands[0] == 'python3':
                        commands = mesonlib.python_command + commands[1:]
                else:
                    # Replace python3 with the actual python3 that we are using
                    if commands[0] == '/usr/bin/env' and commands[1] == 'python3':
                        commands = mesonlib.python_command + commands[2:]
                    elif commands[0].split('/')[-1] == 'python3':
                        commands = mesonlib.python_command + commands[1:]
                return commands + [script]
        except Exception as e:
            mlog.debug(str(e))
        mlog.debug(f'Unusable script {script!r}')
        return None

    def _is_executable(self, path: str) -> bool:
        suffix = os.path.splitext(path)[-1].lower()[1:]
        execmask = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        if mesonlib.is_windows():
            if suffix in self.windows_exts:
                return True
        elif os.stat(path).st_mode & execmask:
            return not os.path.isdir(path)
        return False

    def _search_dir(self, name: str, search_dir: T.Optional[str]) -> T.Optional[list]:
        if search_dir is None:
            return None
        trial = os.path.join(search_dir, name)
        if os.path.exists(trial):
            if self._is_executable(trial):
                return [trial]
            # Now getting desperate. Maybe it is a script file that is
            # a) not chmodded executable, or
            # b) we are on windows so they can't be directly executed.
            return self._shebang_to_cmd(trial)
        else:
            if mesonlib.is_windows():
                for ext in self.windows_exts:
                    trial_ext = f'{trial}.{ext}'
                    if os.path.exists(trial_ext):
                        return [trial_ext]
        return None

    def _search_windows_special_cases(self, name: str, command: str) -> T.List[T.Optional[str]]:
        '''
        Lots of weird Windows quirks:
        1. PATH search for @name returns files with extensions from PATHEXT,
           but only self.windows_exts are executable without an interpreter.
        2. @name might be an absolute path to an executable, but without the
           extension. This works inside MinGW so people use it a lot.
        3. The script is specified without an extension, in which case we have
           to manually search in PATH.
        4. More special-casing for the shebang inside the script.
        '''
        if command:
            # On Windows, even if the PATH search returned a full path, we can't be
            # sure that it can be run directly if it's not a native executable.
            # For instance, interpreted scripts sometimes need to be run explicitly
            # with an interpreter if the file association is not done properly.
            name_ext = os.path.splitext(command)[1]
            if name_ext[1:].lower() in self.windows_exts:
                # Good, it can be directly executed
                return [command]
            # Try to extract the interpreter from the shebang
            commands = self._shebang_to_cmd(command)
            if commands:
                return commands
            return [None]
        # Maybe the name is an absolute path to a native Windows
        # executable, but without the extension. This is technically wrong,
        # but many people do it because it works in the MinGW shell.
        if os.path.isabs(name):
            for ext in self.windows_exts:
                command = f'{name}.{ext}'
                if os.path.exists(command):
                    return [command]
        # On Windows, interpreted scripts must have an extension otherwise they
        # cannot be found by a standard PATH search. So we do a custom search
        # where we manually search for a script with a shebang in PATH.
        search_dirs = self._windows_sanitize_path(os.environ.get('PATH', '')).split(';')
        for search_dir in search_dirs:
            commands = self._search_dir(name, search_dir)
            if commands:
                return commands
        return [None]

    def _search(self, name: str, search_dir: T.Optional[str]) -> T.List[T.Optional[str]]:
        '''
        Search in the specified dir for the specified executable by name
        and if not found search in PATH
        '''
        commands = self._search_dir(name, search_dir)
        if commands:
            return commands
        # If there is a directory component, do not look in PATH
        if os.path.dirname(name) and not os.path.isabs(name):
            return [None]
        # Do a standard search in PATH
        path = os.environ.get('PATH', None)
        if mesonlib.is_windows() and path:
            path = self._windows_sanitize_path(path)
        command = shutil.which(name, path=path)
        if mesonlib.is_windows():
            return self._search_windows_special_cases(name, command)
        # On UNIX-like platforms, shutil.which() is enough to find
        # all executables whether in PATH or with an absolute path
        return [command]

    def found(self) -> bool:
        return self.command[0] is not None

    def get_command(self) -> T.List[str]:
        return self.command[:]

    def get_path(self) -> T.Optional[str]:
        return self.path

    def get_name(self) -> str:
        return self.name


class NonExistingExternalProgram(ExternalProgram):  # lgtm [py/missing-call-to-init]
    "A program that will never exist"

    def __init__(self, name: str = 'nonexistingprogram') -> None:
        self.name = name
        self.command = [None]
        self.path = None

    def __repr__(self) -> str:
        r = '<{} {!r} -> {!r}>'
        return r.format(self.__class__.__name__, self.name, self.command)

    def found(self) -> bool:
        return False


class OverrideProgram(ExternalProgram):

    """A script overriding a program."""


def find_external_program(env: 'Environment', for_machine: MachineChoice, name: str,
                          display_name: str, default_names: T.List[str],
                          allow_default_for_cross: bool = True) -> T.Generator['ExternalProgram', None, None]:
    """Find an external program, checking the cross file plus any default options."""
    potential_names = OrderedSet(default_names)
    potential_names.add(name)
    # Lookup in cross or machine file.
    for potential_name in potential_names:
        potential_cmd = env.lookup_binary_entry(for_machine, potential_name)
        if potential_cmd is not None:
            mlog.debug(f'{display_name} binary for {for_machine} specified from cross file, native file, '
                       f'or env var as {potential_cmd}')
            yield ExternalProgram.from_entry(potential_name, potential_cmd)
            # We never fallback if the user-specified option is no good, so
            # stop returning options.
            return
    mlog.debug(f'{display_name} binary missing from cross or native file, or env var undefined.')
    # Fallback on hard-coded defaults, if a default binary is allowed for use
    # with cross targets, or if this is not a cross target
    if allow_default_for_cross or not (for_machine is MachineChoice.HOST and env.is_cross_build(for_machine)):
        for potential_path in default_names:
            mlog.debug(f'Trying a default {display_name} fallback at', potential_path)
            yield ExternalProgram(potential_path, silent=True)
    else:
        mlog.debug('Default target is not allowed for cross use')
```