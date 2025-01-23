Response:
My thought process to answer the request about `programs.py` goes like this:

1. **Understand the Goal:** The primary goal is to analyze the provided Python code snippet and explain its functionality, especially in the context of reverse engineering, low-level operations, and potential user errors.

2. **Initial Code Scan (Keywords and Structure):** I'll quickly scan the code for keywords and structural elements that give clues about its purpose. I see imports like `os`, `shutil`, `stat`, `re`, and `pathlib`, which suggests file system operations and string manipulation. The presence of classes like `ExternalProgram` and `NonExistingExternalProgram` indicates this code deals with locating and representing external executables.

3. **Focus on `ExternalProgram`:** This class seems central. I'll examine its `__init__` method to understand how it's initialized. It takes a `name` and an optional `command`. It appears to search for the program using `shutil.which` and handles platform-specific logic (Windows). The `found()` method is crucial for determining if the program was located.

4. **Analyze Key Methods:** I'll delve deeper into important methods:
    * `get_version()`:  This clearly aims to retrieve the version of an external program by running it with `--version`. This is directly relevant to reverse engineering as knowing the version of a tool is often the first step.
    * `from_bin_list()` and `from_entry()`: These seem to be factory methods for creating `ExternalProgram` instances, potentially using configuration data.
    * `_shebang_to_cmd()`: This is interesting! It handles shebang lines in scripts, which is common in Linux and important for correctly executing scripts on different platforms, especially Windows. This connects to low-level execution.
    * `_search()` and `_search_dir()`: These are the core logic for finding executables in the file system and along the PATH. The platform-specific handling in `_search_windows_special_cases()` is also important.

5. **Consider the Context (Frida & Meson):** The file path (`frida/subprojects/frida-core/releng/meson/mesonbuild/programs.py`) tells me this is part of Frida and uses the Meson build system. This gives context: the code is likely used during the build process to find necessary external tools. This context is important for understanding why specific platform-specific handling is present.

6. **Identify Connections to Reverse Engineering:**
    * Finding external tools (debuggers, disassemblers, etc.) is crucial for reverse engineering. The code explicitly deals with locating these.
    * The `get_version()` method helps in identifying the exact tool version, which can be important as different versions might have different behaviors or vulnerabilities.

7. **Identify Connections to Low-Level Operations:**
    * Handling shebangs (`_shebang_to_cmd()`) relates to how operating systems execute scripts.
    * Searching the PATH and dealing with platform-specific executable extensions (`.exe`, etc.) are low-level OS concepts.
    * The Windows-specific logic highlights the differences in how executables are handled on that platform.

8. **Infer Logical Reasoning:** The code performs logical reasoning by:
    * Prioritizing user-specified paths over defaults.
    * Implementing platform-specific search strategies.
    * Checking for executability.
    * Attempting to extract interpreter information from shebang lines.

9. **Identify Potential User Errors:**  Common user errors might involve:
    * Incorrectly specifying the path to an external program in configuration files.
    * Not having the required program installed or in the PATH.
    * Platform-specific issues (e.g., assuming a script is executable on Windows without the correct interpreter).

10. **Trace User Operations:** How does a user interact with this code?  The most likely scenario is through the Meson build system. When a build configuration requires an external tool, Meson will use this code to find it. The user might configure the location of these tools in a cross-compilation file or environment variables.

11. **Structure the Answer:**  I'll organize the answer logically, starting with a general overview of the file's purpose, then detailing its functionalities, and finally addressing the specific points about reverse engineering, low-level aspects, logic, user errors, and debugging. Using clear headings and bullet points will improve readability.

12. **Refine and Elaborate:**  I'll review my initial thoughts and add more details and explanations where needed. For example, for the reverse engineering aspect, I'll provide concrete examples of tools that might be located using this code. For user errors, I will provide specific scenarios.

By following this process, I can break down the code into manageable parts, understand its purpose and functionality, and address all aspects of the user's request in a comprehensive and structured manner.
这个 Python 源代码文件 `programs.py` 是 Frida 动态 instrumentation 工具中 Meson 构建系统的一部分，它主要负责管理和查找构建过程中需要用到的外部程序（例如编译器、链接器等）。

**功能列举:**

1. **定义 `ExternalProgram` 类:**  这是一个核心类，用于表示系统上找到的外部程序。它存储了程序的名字、路径以及执行命令。
2. **程序查找:**  `ExternalProgram` 类能够根据程序名在系统 PATH 环境变量中查找可执行文件。它还支持在指定的目录中查找。
3. **处理 Windows 特性:** 针对 Windows 平台，它会处理可执行文件的扩展名（.exe, .com, .bat 等）以及带有 shebang 行的脚本文件。
4. **解析 Shebang:**  对于 Linux 和 macOS 等系统，以及 Windows 上的脚本文件，它能够解析文件开头的 shebang 行 (例如 `#!/usr/bin/python3`)，从而确定执行该脚本所需的解释器。
5. **获取程序版本:**  `ExternalProgram` 类提供了 `get_version` 方法，用于执行程序并尝试解析其输出，以获取程序的版本号。
6. **处理未找到的程序:** 定义了 `NonExistingExternalProgram` 类，用于表示查找失败的程序。
7. **支持覆盖程序:** 定义了 `OverrideProgram` 类，可能用于在构建过程中覆盖默认的程序。
8. **提供查找外部程序的辅助函数:** `find_external_program` 函数用于在交叉编译环境或指定默认名称列表中查找外部程序。

**与逆向方法的关联及举例:**

这个文件本身并不是一个直接的逆向工具，但它在 Frida 的构建过程中扮演着重要的角色，而 Frida 本身是一个强大的动态逆向工具。

* **查找必要的构建工具:**  逆向工程中，经常需要编译和构建工具（例如，将 C/C++ 代码编译成目标平台的库）。`programs.py` 确保了 Frida 的构建过程能够找到所需的编译器（如 GCC, Clang）、链接器、汇编器等。例如，在构建 Frida 的 Android 版本时，它需要找到 Android NDK 提供的 `arm-linux-androideabi-gcc` 或 `aarch64-linux-android-clang` 等交叉编译工具。
    * **举例:** 假设构建 Frida 的 Android 版本，`programs.py` 可能会查找名为 `cc` 或 `gcc` 的程序。如果配置了 Android NDK 的路径，它会找到 NDK 中的交叉编译器。这对于编译 Frida 注入到 Android 进程中的 Agent 代码至关重要。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例:**

* **二进制可执行文件:** `programs.py` 涉及到识别和查找二进制可执行文件，理解不同操作系统上可执行文件的格式和加载方式。
    * **举例:**  在 Windows 上，它会检查文件的扩展名是否在 `windows_exts` 中，而在 Linux 上则会检查文件的执行权限位。
* **PATH 环境变量:**  依赖于操作系统提供的 PATH 环境变量来定位可执行文件，这是操作系统管理可执行文件路径的基础机制。
* **Shebang 行:**  理解 Linux 和类 Unix 系统中 shebang 行的作用，以及如何解析它来确定脚本的解释器。
    * **举例:** 当遇到一个以 `#!/usr/bin/python3` 开头的脚本时，`_shebang_to_cmd` 方法会识别出需要使用 `python3` 来执行这个脚本。
* **交叉编译:**  `find_external_program` 函数在交叉编译环境中查找目标平台的构建工具，这涉及到理解不同架构和操作系统之间的差异。
    * **举例:** 在构建 Android 平台的 Frida 组件时，需要使用运行在主机（例如 Linux 或 macOS）上的交叉编译器来编译生成在 Android 设备上运行的二进制代码。
* **Android NDK:**  当构建 Frida 的 Android 版本时，需要使用 Android NDK 提供的工具链。`programs.py` 需要能够找到这些工具链中的编译器、链接器等。

**逻辑推理及假设输入与输出:**

* **假设输入:** `name = "python3"`, 系统 PATH 环境变量中包含 `/usr/bin`，且 `/usr/bin/python3` 是一个可执行文件。
* **逻辑推理:** `ExternalProgram` 的 `_search` 方法会首先在指定的 `search_dir` 中查找，如果未找到则在 PATH 环境变量中查找。`shutil.which` 函数会在 PATH 中搜索名为 "python3" 的可执行文件。
* **输出:** `ExternalProgram` 实例的 `command` 属性会是 `['/usr/bin/python3']`，`path` 属性会是 `/usr/bin/python3`，`found()` 方法返回 `True`。

* **假设输入 (Windows):** `name = "notepad"`, 系统 PATH 环境变量中包含 `C:\Windows\System32`, 且 `C:\Windows\System32\notepad.exe` 存在。
* **逻辑推理:** 在 Windows 上，`_search_windows_special_cases` 方法会利用 `shutil.which` 在 PATH 中查找 "notepad"，由于 Windows 会自动补全扩展名，因此会找到 `notepad.exe`。
* **输出:** `ExternalProgram` 实例的 `command` 属性会是 `['C:\\Windows\\System32\\notepad.exe']`，`path` 属性会是 `C:\Windows\System32\notepad.exe`，`found()` 方法返回 `True`。

**涉及用户或者编程常见的使用错误及举例:**

* **未安装必要的构建工具:** 用户在构建 Frida 时，如果系统中缺少必要的编译器或链接器，`programs.py` 将无法找到这些程序。
    * **举例:** 如果用户尝试构建 Frida 但没有安装 GCC 或 Clang，Meson 配置阶段会报错，提示找不到 C 编译器。
* **环境变量配置错误:**  如果用户没有正确配置 PATH 环境变量，导致系统无法找到所需的程序。
    * **举例:** 用户可能安装了 Android NDK，但没有将其工具链路径添加到 PATH 环境变量中，导致 Frida 的构建脚本无法找到交叉编译器。
* **拼写错误:** 用户在配置文件中指定外部程序名称时可能存在拼写错误。
    * **举例:** 用户可能在 Meson 的配置文件中将编译器名称拼写为 "gc" 而不是 "gcc"。
* **权限问题:**  用户可能尝试使用没有执行权限的文件作为外部程序。
    * **举例:** 用户可能错误地指定了一个脚本文件，但该文件没有设置执行权限，导致 `programs.py` 认为该程序不可用（除非能够解析 shebang）。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试构建 Frida:** 用户从 Frida 的源代码仓库下载或克隆了代码，并尝试使用 Meson 构建系统进行构建，通常会执行类似 `meson setup build` 或 `meson compile -C build` 的命令。
2. **Meson 解析构建配置:** Meson 在 `setup` 阶段会读取 `meson.build` 文件以及相关的配置文件（例如交叉编译配置文件），这些文件中可能定义了需要使用的外部程序。
3. **调用 `programs.py` 中的代码:** 当 Meson 需要查找特定的外部程序时，例如 C 编译器、链接器等，它会调用 `frida/subprojects/frida-core/releng/meson/mesonbuild/programs.py` 文件中的函数，特别是 `find_external_program` 或直接创建 `ExternalProgram` 实例。
4. **程序查找过程:** `programs.py` 中的代码会根据提供的程序名和可能的搜索路径（包括 PATH 环境变量和配置文件中指定的路径）来查找程序。
5. **查找结果反馈:**  如果找到程序，`ExternalProgram` 实例会被创建并存储程序的信息；如果找不到，会创建 `NonExistingExternalProgram` 实例，并可能导致构建过程失败并输出错误信息。

**作为调试线索:**

* **构建失败信息:** 如果构建过程中出现找不到特定程序的错误，可以查看 Meson 的输出信息，通常会包含尝试查找的程序名称。
* **检查 PATH 环境变量:** 检查构建环境的 PATH 环境变量是否包含了所需的外部程序所在的目录。
* **检查 Meson 配置文件:** 查看 `meson.build` 文件以及相关的交叉编译配置文件，确认外部程序的名称和路径是否正确配置。
* **使用 `meson introspect` 命令:** Meson 提供了 `introspect` 命令，可以用来查看构建系统的内部状态，包括找到的程序信息。例如，可以使用 `meson introspect --buildoptions` 查看构建选项，或者使用其他相关的 introspect 子命令查看程序信息。
* **修改 `programs.py` 进行调试:**  在调试环境中，可以临时修改 `programs.py` 文件，例如添加 `print` 语句来查看查找路径、找到的程序信息等，以便更深入地了解程序查找的过程。

总而言之，`programs.py` 是 Frida 构建系统中一个基础但关键的组件，负责管理外部程序的查找和表示，确保构建过程能够找到所有必要的工具。它与逆向工程的联系在于它支撑了 Frida 这个逆向工具的构建过程，并且其内部实现涉及了操作系统底层的一些概念。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/programs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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